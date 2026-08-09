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

OccurrenceBuilder is the private construction representation. RawProjectionRequest
is the separate escape hatch for single-format entries.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field, fields
from datetime import datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from evidenceforge.events.authentication import RemoteAuthenticationPlan
from evidenceforge.events.contexts import (
    AccountManagementContext,
    AuthContext,
    DhcpContext,
    DnsContext,
    EmailContext,
    FileContext,
    FileTransferContext,
    FirewallContext,
    GroupMembershipContext,
    HostContext,
    HttpContext,
    IdsAlertPlan,
    ImageLoadContext,
    KerberosContext,
    NatContext,
    NtpContext,
    OcspContext,
    PeContext,
    ProcessAccessContext,
    ProcessContext,
    ProxyContext,
    RegistryContext,
    RemoteThreadContext,
    ScheduledTaskContext,
    ServiceContext,
    ShellContext,
    SmtpContext,
    SslContext,
    SyslogContext,
    WeirdContext,
    X509Context,
)
from evidenceforge.events.contracts import EventKind, SemanticOccurrenceKey, ShadowSealResult
from evidenceforge.events.cryptography import (
    OcspTransactionPlan,
    TlsCertificatePresentationPlan,
)
from evidenceforge.events.identity import EventIdentityPlan
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.network import NetworkSensorObservation, NetworkTransactionPlan
from evidenceforge.events.protocol import ProtocolTransactionPlan

if TYPE_CHECKING:
    from evidenceforge.generation.source_timing import SourceTimingPlan


@dataclass
class OccurrenceBuilder:
    """Private mutable construction surface for one logical occurrence.

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
    remote_auth: RemoteAuthenticationPlan | None = None
    process: ProcessContext | None = None
    network: NetworkTransactionPlan | None = None
    dns: DnsContext | None = None
    email: EmailContext | None = None
    smtp: SmtpContext | None = None
    file: FileContext | None = None
    registry: RegistryContext | None = None
    remote_thread: RemoteThreadContext | None = None
    process_access: ProcessAccessContext | None = None
    ids_alerts: tuple[IdsAlertPlan, ...] = ()
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
    file_transfers: list[FileTransferContext] = field(default_factory=list)
    x509: X509Context | None = None
    x509_chain: list[X509Context] = field(default_factory=list)
    tls_presentation: TlsCertificatePresentationPlan | None = None
    dhcp: DhcpContext | None = None
    ntp: NtpContext | None = None
    ocsp: OcspContext | None = None
    ocsp_transaction: OcspTransactionPlan | None = None
    pe: PeContext | None = None
    proxy: ProxyContext | None = None

    # Firewall decision context (Cisco ASA)
    firewall: FirewallContext | None = None

    # NAT translation context (Cisco ASA)
    nat: NatContext | None = None

    # Host-local event: skip network-sensor formats (Zeek/Snort) but still
    # emit to host-based formats (eCAR, Windows, Sysmon).  Set when src_ip == dst_ip.
    local_only: bool = False

    # Set by the storyline engine for events whose timestamp must not be shifted
    # by per-host monotonic-clock normalisation or session-activity clamping.
    storyline_origin: bool = False

    # Provenance-only cluster identifier for events generated while executing a
    # storyline/red-herring context. Unlike storyline_origin, this does not
    # change timestamp normalization or source-native rendering behavior.
    storyline_cluster_id: str | None = None

    # Planned source-native observation times keyed by source family/profile.
    # OccurrenceBuilder.timestamp remains canonical world time.
    source_timing: SourceTimingPlan | None = None

    # Correlated action lifecycle and action-relative semantic occurrence identity.
    occurrence_key: SemanticOccurrenceKey | None = None
    # Immutable contract snapshot captured after identity planning and enforced by dispatch before
    # state, routing, observation, or projection.
    contract_seal: ShadowSealResult | None = None
    lifecycle: ActionLifecycleContext | None = None
    identity_plan: EventIdentityPlan | None = None
    network_observations: tuple[NetworkSensorObservation, ...] = ()
    network_observations_planned: bool = False

    # Sensor routing metadata (not a context — set by dispatcher)
    # Maps format_name → list of sensor hostnames that produce that format
    _sensor_hostnames_by_format: dict[str, list[str]] = field(default_factory=dict)
    _visible_network_formats: set[str] = field(default_factory=set)
    # Format names that survived source-observation policy for this dispatch.
    # Emitters use this to avoid rendering source-local references to sibling
    # rows that the same observation profile intentionally dropped.
    _observed_formats: set[str] = field(default_factory=set)
    _source_observation_status: str = "visible"

    @property
    def occurrence_id(self) -> str:
        """Return the stable action-relative occurrence identifier."""

        return self.occurrence_key.occurrence_id if self.occurrence_key is not None else ""

    @property
    def protocol(self) -> ProtocolTransactionPlan:
        """Compose the final protocol aggregate from private construction fields."""

        return ProtocolTransactionPlan.compose(
            ssl=self.ssl,
            http=self.http,
            file_transfer=self.file_transfer,
            file_transfers=self.file_transfers,
            x509=self.x509,
            x509_chain=self.x509_chain,
            tls_presentation=self.tls_presentation,
            ocsp=self.ocsp,
            ocsp_transaction=self.ocsp_transaction,
            pe=self.pe,
            proxy=self.proxy,
        )

    def seal(self) -> CanonicalOccurrence:
        """Deep-snapshot this builder into the immutable publication boundary."""

        if self.contract_seal is None or not self.contract_seal.valid:
            raise ValueError("Occurrence builders require a valid contract seal before publication")
        if self.occurrence_key is None:
            raise ValueError("Occurrence builders require semantic identity before publication")
        memo: dict[int, Any] = {}
        values = {
            item.name: deepcopy(getattr(self, item.name), memo)
            for item in fields(CanonicalOccurrence)
            if item.name
            not in {
                "_sensor_hostnames_by_format",
                "_visible_network_formats",
                "_observed_formats",
            }
        }
        values["event_type"] = EventKind(self.event_type)
        values["_sensor_hostnames_by_format"] = MappingProxyType(
            {
                format_name: tuple(sensor_names)
                for format_name, sensor_names in deepcopy(
                    self._sensor_hostnames_by_format,
                    memo,
                ).items()
            }
        )
        values["_observed_formats"] = frozenset(self._observed_formats)
        values["_visible_network_formats"] = frozenset(self._visible_network_formats)
        return CanonicalOccurrence(**values)


@dataclass(frozen=True, slots=True)
class CanonicalOccurrence:
    """Immutable occurrence snapshot accepted by state, observation, and projection."""

    timestamp: datetime
    event_type: EventKind
    src_host: HostContext | None = None
    dst_host: HostContext | None = None
    auth: AuthContext | None = None
    remote_auth: RemoteAuthenticationPlan | None = None
    process: ProcessContext | None = None
    network: NetworkTransactionPlan | None = None
    dns: DnsContext | None = None
    email: EmailContext | None = None
    smtp: SmtpContext | None = None
    file: FileContext | None = None
    registry: RegistryContext | None = None
    remote_thread: RemoteThreadContext | None = None
    process_access: ProcessAccessContext | None = None
    ids_alerts: tuple[IdsAlertPlan, ...] = ()
    image_load: ImageLoadContext | None = None
    syslog: SyslogContext | None = None
    weird: WeirdContext | None = None
    kerberos: KerberosContext | None = None
    shell: ShellContext | None = None
    service: ServiceContext | None = None
    scheduled_task: ScheduledTaskContext | None = None
    group_membership: GroupMembershipContext | None = None
    account_management: AccountManagementContext | None = None
    protocol: ProtocolTransactionPlan = ProtocolTransactionPlan()
    dhcp: DhcpContext | None = None
    ntp: NtpContext | None = None
    firewall: FirewallContext | None = None
    nat: NatContext | None = None
    local_only: bool = False
    storyline_origin: bool = False
    storyline_cluster_id: str | None = None
    source_timing: SourceTimingPlan | None = None
    occurrence_key: SemanticOccurrenceKey | None = None
    contract_seal: ShadowSealResult | None = None
    lifecycle: ActionLifecycleContext | None = None
    identity_plan: EventIdentityPlan | None = None
    network_observations: tuple[NetworkSensorObservation, ...] = ()
    network_observations_planned: bool = False
    _sensor_hostnames_by_format: Mapping[str, tuple[str, ...]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    _visible_network_formats: frozenset[str] = frozenset()
    _observed_formats: frozenset[str] = frozenset()
    _source_observation_status: str = "visible"

    def __post_init__(self) -> None:
        """Reject construction that bypassed the validated builder boundary."""

        if self.contract_seal is None or not self.contract_seal.valid:
            raise ValueError("Canonical occurrences require a valid contract seal")
        if self.occurrence_key is None:
            raise ValueError("Canonical occurrences require semantic identity")

    @property
    def occurrence_id(self) -> str:
        """Return the stable action-relative occurrence identifier."""

        assert self.occurrence_key is not None
        return self.occurrence_key.occurrence_id


@dataclass(frozen=True, slots=True)
class RawProjectionRequest:
    """Source-local escape hatch that never enters the canonical event model.

    Use for: background noise that only appears in one format, simple heartbeats,
    or events that don't yet fit the context model.
    """

    timestamp: datetime
    target_format: str  # Emitter dict key (e.g., "syslog", "zeek_conn")
    data: dict[str, Any]
    local_only: bool = False
    storyline_cluster_id: str | None = None

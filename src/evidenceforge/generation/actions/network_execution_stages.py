# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Ephemeral typed values between canonical network transaction stages.

These records carry existing references; they own no claims, RNGs, or durable state.
The transaction boundary remains the sole cancellation, sealing, and recovery owner.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    import random
    from datetime import datetime, timedelta

    from evidenceforge.events.base import OccurrenceBuilder
    from evidenceforge.events.contexts import (
        DnsContext,
        EmailContext,
        FileTransferContext,
        FirewallContext,
        HostContext,
        HttpContext,
        IdsAlertPlan,
        OcspContext,
        PeContext,
        ProcessContext,
        ProxyContext,
        SmtpContext,
        X509Context,
    )
    from evidenceforge.events.dispatcher import (
        PreparedDeferredSessionPublicationBatch,
        PreparedDispatch,
        PreparedNetworkDependentBatch,
    )
    from evidenceforge.events.network import NetworkSensorObservation
    from evidenceforge.generation.actions.network_connection import (
        DeferredSessionNetworkAuthority,
        PersistentSmbApplicationIntent,
        PersistentSmbRootIntent,
    )
    from evidenceforge.generation.actions.network_transaction_planner import _NetworkOccurrenceDraft
    from evidenceforge.generation.actions.proxy_transaction import ExplicitProxyRequestPreparation
    from evidenceforge.generation.deferred_session_composition import DeferredSessionComposition
    from evidenceforge.generation.http_channels import HttpChannelAffinity
    from evidenceforge.generation.lifecycle_authority import (
        DeferredSessionPublishedNetworkResult,
        LifecyclePreparedNetworkResult,
    )
    from evidenceforge.generation.lifecycle_registry import LifecycleClosedTransportAdmissionToken
    from evidenceforge.generation.network_runtime import (
        NetworkTransactionPreparation,
        PreparedNetworkTransactionRoot,
    )
    from evidenceforge.generation.persistent_smb_continuation import (
        PersistentSmbTerminalContinuation,
        PersistentSmbTerminalContinuationAuthority,
    )
    from evidenceforge.generation.smb_channels import SmbChannelAdmissionToken
    from evidenceforge.generation.state_manager import (
        ConnectionMaterializationMode,
        MaterializationBatchPlan,
        SmbFileMutationJournal,
    )
    from evidenceforge.models.scenario import System
    from evidenceforge.models.state import RunningProcess


class PreparedResponderProcess(Protocol):
    """The responder's existing frozen source publication."""

    publication: PreparedDispatch


class PreparedNetworkResponder(Protocol):
    """The responder capability consumed by network preparation."""

    responding_pid: int
    batch: MaterializationBatchPlan | None
    processes: tuple[PreparedResponderProcess, ...]


@dataclass(frozen=True)
class NetworkRequestFacts:
    """Stable caller policy and resolved request facts, shared through publication."""

    automatic_source_port: bool
    caller_owned_pid: int | None
    caller_provided_conn_state: bool
    caller_provided_duration: bool
    caller_provided_payload: bool
    command_http_needs_response_size: bool
    explicit_orig_bytes: int | None
    explicit_resp_bytes: int | None
    parent_action_group_id: str | None
    preserve_explicit_payload: bool
    preserve_start_time: bool
    suppress_application_side_effects: bool
    ssh_attempted_username: str | None
    kerberos_prerequisite_success: bool
    stable_id: str
    local_only: bool
    http_application_layer_only: bool
    is_fw_deny: bool
    is_tcp_probe: bool
    dns_server_ips: set[str]
    packet_overhead_bytes: int | None
    deferred_kerberos_duration_proto: str | None
    kerberos_dc_hostname: str | None


@dataclass(frozen=True)
class ResolvedNetworkEndpoints:
    """Resolved endpoint identity; transport returns revised tuple facts when allocated."""

    dst_ip: str
    dst_port: int
    hostname: str | None
    hostname_was_explicit: bool
    resolved_source_system: System | None
    source_os_category: str
    source_system: System | None
    src_ip: str
    src_port: int | None
    state_source_hostname: str
    state_source_system: str
    src_ip_is_local: bool
    dst_ip_is_local: bool
    tls_hostname: str | None
    target_system: System | None = None
    dst_host_ctx: HostContext | None = None


@dataclass(frozen=True)
class NetworkProtocolEvidence:
    """Protocol inputs and accounting before canonical evidence assembly."""

    dns: DnsContext | None
    email: EmailContext | None
    file_transfer: FileTransferContext | None
    file_transfers: tuple[FileTransferContext, ...]
    firewall: FirewallContext | None
    http: HttpContext | None
    ntp_timing: tuple[float, float, float, timedelta] | None
    ocsp: OcspContext | None
    pe: PeContext | None
    proxy: ProxyContext | None
    smtp: SmtpContext | None
    x509: X509Context | None
    x509_chain: tuple[X509Context, ...]
    orig_bytes: int | None
    resp_bytes: int | None
    duration: float | None
    conn_state: str | None
    proto: str
    service: str | None
    ids_alerts: list[IdsAlertPlan]


@dataclass(frozen=True)
class NetworkApplicationIntents:
    """Existing application and deferred-session authorities, without new ownership."""

    persistent_smb_application_intent: PersistentSmbApplicationIntent | None
    persistent_smb_intent: PersistentSmbRootIntent | None
    persistent_smb_file_journal: SmbFileMutationJournal | None
    persistent_smb_terminal_authority: PersistentSmbTerminalContinuationAuthority | None
    persistent_smb_terminal_continuation: PersistentSmbTerminalContinuation | None
    deferred_authority: DeferredSessionNetworkAuthority | None
    http_channel_affinity: HttpChannelAffinity | None


@dataclass(frozen=True)
class NetworkPublicationInputs:
    """Canonical evidence and endpoint attribution shared by preparation, commit and publication."""

    facts: NetworkRequestFacts
    endpoints: ResolvedNetworkEndpoints
    event: OccurrenceBuilder
    generic_ssh_preauth_pid: int | None
    prepared_responder: PreparedNetworkResponder | None
    process_ctx: ProcessContext | None
    pid: int
    time: datetime
    uid: str
    committed_suppressed: bool


@dataclass(frozen=True)
class PreparedNetworkSources:
    """Prepared source work retained unchanged across the canonical commit boundary."""

    prepared_dispatch: PreparedDispatch | None
    prepared_multipart_batch: PreparedNetworkDependentBatch | None
    materialization_mode: ConnectionMaterializationMode


@dataclass(frozen=True)
class ResolvedNetworkRequest:
    """Resolve the request and existing owners before opening transaction preparation."""

    facts: NetworkRequestFacts
    endpoints: ResolvedNetworkEndpoints
    protocol: NetworkProtocolEvidence
    applications: NetworkApplicationIntents
    explicit_proxy_request_preparation: ExplicitProxyRequestPreparation | None
    pid: int
    process_image: str | None
    resolved_process: RunningProcess | None
    responding_pid: int
    reused_http_conn_id: str
    reused_http_uid: str
    time: datetime


@dataclass(frozen=True)
class PlannedNetworkTransport:
    """Plan transport identity, accounting, and the occurrence draft under one boundary."""

    facts: NetworkRequestFacts
    endpoints: ResolvedNetworkEndpoints
    protocol: NetworkProtocolEvidence
    applications: NetworkApplicationIntents
    canonical_terminal_duration: float | None
    committed_suppressed: bool
    event: _NetworkOccurrenceDraft
    generic_ssh_preauth_pid: int | None
    network_preparation: NetworkTransactionPreparation
    overhead: int
    owner_rng: random.Random
    prepare_generic_smb_responder: bool
    prepare_generic_ssh_responder: bool
    prepared_responder: PreparedNetworkResponder | None
    responding_pid: int
    rng: random.Random
    time: datetime
    uid: str


@dataclass(frozen=True)
class PlannedNetworkEvidence:
    """Plan protocol evidence and canonical timing before preparing publication."""

    publication: NetworkPublicationInputs
    applications: NetworkApplicationIntents
    network_preparation: NetworkTransactionPreparation
    owner_rng: random.Random
    rng: random.Random
    persistent_smb_batch: MaterializationBatchPlan | None


@dataclass(frozen=True)
class PreparedNetworkPublication:
    """Assemble and validate state, lifecycle, and source publication capabilities."""

    publication: NetworkPublicationInputs
    sources: PreparedNetworkSources
    applications: NetworkApplicationIntents
    owner_rng: random.Random
    application_token: SmbChannelAdmissionToken | None
    deferred_composition: DeferredSessionComposition | None
    deferred_publication_batch: PreparedDeferredSessionPublicationBatch | None
    lifecycle_token: LifecycleClosedTransportAdmissionToken | None
    persistent_smb_observations: tuple[NetworkSensorObservation, ...]
    root: PreparedNetworkTransactionRoot


@dataclass(frozen=True)
class CommittedNetworkPublication:
    """Commit through the existing authority and preserve exact receipt recovery."""

    publication: NetworkPublicationInputs
    sources: PreparedNetworkSources
    deferred_published: DeferredSessionPublishedNetworkResult | None
    materialized: LifecyclePreparedNetworkResult

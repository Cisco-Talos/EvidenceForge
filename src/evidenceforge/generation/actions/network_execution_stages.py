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
class ResolvedNetworkRequest:
    """Resolve the request and existing owners before opening transaction preparation."""

    automatic_source_port: bool
    caller_owned_pid: int | None
    caller_provided_conn_state: bool
    caller_provided_duration: bool
    caller_provided_payload: bool
    command_http_needs_response_size: bool
    conn_state: str | None
    deferred_authority: DeferredSessionNetworkAuthority | None
    deferred_kerberos_duration_proto: str | None
    dns: DnsContext | None
    dns_server_ips: set[str]
    dst_ip: str
    dst_ip_is_local: bool
    dst_port: int
    duration: float | None
    email: EmailContext | None
    explicit_orig_bytes: int | None
    explicit_proxy_request_preparation: ExplicitProxyRequestPreparation | None
    explicit_resp_bytes: int | None
    file_transfer: FileTransferContext | None
    file_transfers: tuple[FileTransferContext, ...]
    firewall: FirewallContext | None
    hostname: str | None
    hostname_was_explicit: bool
    http: HttpContext | None
    http_application_layer_only: bool
    http_channel_affinity: HttpChannelAffinity | None
    ids_alerts: list[IdsAlertPlan]
    is_fw_deny: bool
    is_tcp_probe: bool
    kerberos_dc_hostname: str | None
    kerberos_prerequisite_success: bool
    local_only: bool
    ntp_timing: tuple[float, float, float, timedelta] | None
    ocsp: OcspContext | None
    orig_bytes: int | None
    packet_overhead_bytes: int | None
    parent_action_group_id: str | None
    pe: PeContext | None
    persistent_smb_application_intent: PersistentSmbApplicationIntent | None
    persistent_smb_file_journal: SmbFileMutationJournal | None
    persistent_smb_intent: PersistentSmbRootIntent | None
    persistent_smb_terminal_authority: PersistentSmbTerminalContinuationAuthority | None
    persistent_smb_terminal_continuation: PersistentSmbTerminalContinuation | None
    pid: int
    preserve_explicit_payload: bool
    preserve_start_time: bool
    process_image: str | None
    proto: str
    proxy: ProxyContext | None
    resolved_process: RunningProcess | None
    resolved_source_system: System | None
    resp_bytes: int | None
    responding_pid: int
    reused_http_conn_id: str
    reused_http_uid: str
    service: str | None
    smtp: SmtpContext | None
    source_os_category: str
    source_system: System | None
    src_ip: str
    src_ip_is_local: bool
    src_port: int | None
    ssh_attempted_username: str | None
    stable_id: str
    state_source_hostname: str
    state_source_system: str
    suppress_application_side_effects: bool
    time: datetime
    tls_hostname: str | None
    x509: X509Context | None
    x509_chain: tuple[X509Context, ...]


@dataclass(frozen=True)
class PlannedNetworkTransport:
    """Plan transport identity, accounting, and the occurrence draft under one boundary."""

    automatic_source_port: bool
    caller_owned_pid: int | None
    caller_provided_conn_state: bool
    canonical_terminal_duration: float | None
    committed_suppressed: bool
    conn_state: str | None
    deferred_authority: DeferredSessionNetworkAuthority | None
    dns: DnsContext | None
    dns_server_ips: set[str]
    dst_host_ctx: HostContext | None
    dst_ip: str
    dst_port: int
    duration: float | None
    email: EmailContext | None
    event: _NetworkOccurrenceDraft
    explicit_orig_bytes: int | None
    explicit_resp_bytes: int | None
    file_transfer: FileTransferContext | None
    file_transfers: tuple[FileTransferContext, ...]
    firewall: FirewallContext | None
    generic_ssh_preauth_pid: int | None
    hostname: str | None
    hostname_was_explicit: bool
    http: HttpContext | None
    http_application_layer_only: bool
    http_channel_affinity: HttpChannelAffinity | None
    ids_alerts: list[IdsAlertPlan]
    is_fw_deny: bool
    kerberos_prerequisite_success: bool
    local_only: bool
    network_preparation: NetworkTransactionPreparation
    ntp_timing: tuple[float, float, float, timedelta] | None
    ocsp: OcspContext | None
    orig_bytes: int | None
    overhead: int
    owner_rng: random.Random
    parent_action_group_id: str | None
    pe: PeContext | None
    persistent_smb_application_intent: PersistentSmbApplicationIntent | None
    persistent_smb_file_journal: SmbFileMutationJournal | None
    persistent_smb_intent: PersistentSmbRootIntent | None
    persistent_smb_terminal_authority: PersistentSmbTerminalContinuationAuthority | None
    persistent_smb_terminal_continuation: PersistentSmbTerminalContinuation | None
    prepare_generic_smb_responder: bool
    prepare_generic_ssh_responder: bool
    prepared_responder: PreparedNetworkResponder | None
    preserve_explicit_payload: bool
    preserve_start_time: bool
    proto: str
    proxy: ProxyContext | None
    resolved_source_system: System | None
    resp_bytes: int | None
    responding_pid: int
    rng: random.Random
    service: str | None
    smtp: SmtpContext | None
    source_os_category: str
    source_system: System | None
    src_ip: str
    src_port: int | None
    ssh_attempted_username: str | None
    stable_id: str
    state_source_hostname: str
    state_source_system: str
    suppress_application_side_effects: bool
    target_system: System | None
    time: datetime
    tls_hostname: str | None
    uid: str
    x509: X509Context | None
    x509_chain: tuple[X509Context, ...]


@dataclass(frozen=True)
class PlannedNetworkEvidence:
    """Plan protocol evidence and canonical timing before preparing publication."""

    caller_owned_pid: int | None
    committed_suppressed: bool
    deferred_authority: DeferredSessionNetworkAuthority | None
    dst_host_ctx: HostContext | None
    dst_ip: str
    dst_port: int
    event: OccurrenceBuilder
    generic_ssh_preauth_pid: int | None
    hostname: str | None
    http_channel_affinity: HttpChannelAffinity | None
    kerberos_prerequisite_success: bool
    network_preparation: NetworkTransactionPreparation
    owner_rng: random.Random
    parent_action_group_id: str | None
    persistent_smb_application_intent: PersistentSmbApplicationIntent | None
    persistent_smb_batch: MaterializationBatchPlan | None
    persistent_smb_file_journal: SmbFileMutationJournal | None
    persistent_smb_intent: PersistentSmbRootIntent | None
    persistent_smb_terminal_authority: PersistentSmbTerminalContinuationAuthority | None
    persistent_smb_terminal_continuation: PersistentSmbTerminalContinuation | None
    pid: int
    prepared_responder: PreparedNetworkResponder | None
    process_ctx: ProcessContext | None
    resolved_source_system: System | None
    rng: random.Random
    source_system: System | None
    src_ip: str
    src_port: int | None
    ssh_attempted_username: str | None
    state_source_hostname: str
    state_source_system: str
    suppress_application_side_effects: bool
    target_system: System | None
    time: datetime
    uid: str


@dataclass(frozen=True)
class PreparedNetworkPublication:
    """Assemble and validate state, lifecycle, and source publication capabilities."""

    application_token: SmbChannelAdmissionToken | None
    caller_owned_pid: int | None
    committed_suppressed: bool
    deferred_authority: DeferredSessionNetworkAuthority | None
    deferred_composition: DeferredSessionComposition | None
    deferred_publication_batch: PreparedDeferredSessionPublicationBatch | None
    dst_host_ctx: HostContext | None
    dst_ip: str
    dst_port: int
    event: OccurrenceBuilder
    generic_ssh_preauth_pid: int | None
    kerberos_prerequisite_success: bool
    lifecycle_token: LifecycleClosedTransportAdmissionToken | None
    materialization_mode: ConnectionMaterializationMode
    owner_rng: random.Random
    parent_action_group_id: str | None
    persistent_smb_file_journal: SmbFileMutationJournal | None
    persistent_smb_intent: PersistentSmbRootIntent | None
    persistent_smb_observations: tuple[NetworkSensorObservation, ...]
    persistent_smb_terminal_authority: PersistentSmbTerminalContinuationAuthority | None
    persistent_smb_terminal_continuation: PersistentSmbTerminalContinuation | None
    pid: int
    prepared_dispatch: PreparedDispatch | None
    prepared_multipart_batch: PreparedNetworkDependentBatch | None
    prepared_responder: PreparedNetworkResponder | None
    process_ctx: ProcessContext | None
    resolved_source_system: System | None
    root: PreparedNetworkTransactionRoot
    source_system: System | None
    src_ip: str
    src_port: int | None
    ssh_attempted_username: str | None
    suppress_application_side_effects: bool
    target_system: System | None
    time: datetime
    uid: str


@dataclass(frozen=True)
class CommittedNetworkPublication:
    """Commit through the existing authority and preserve exact receipt recovery."""

    caller_owned_pid: int | None
    committed_suppressed: bool
    deferred_published: DeferredSessionPublishedNetworkResult | None
    dst_host_ctx: HostContext | None
    dst_ip: str
    dst_port: int
    event: OccurrenceBuilder
    generic_ssh_preauth_pid: int | None
    kerberos_prerequisite_success: bool
    materialization_mode: ConnectionMaterializationMode
    materialized: LifecyclePreparedNetworkResult
    parent_action_group_id: str | None
    pid: int
    prepared_dispatch: PreparedDispatch | None
    prepared_multipart_batch: PreparedNetworkDependentBatch | None
    prepared_responder: PreparedNetworkResponder | None
    process_ctx: ProcessContext | None
    resolved_source_system: System | None
    source_system: System | None
    src_ip: str
    src_port: int | None
    ssh_attempted_username: str | None
    suppress_application_side_effects: bool
    target_system: System | None
    time: datetime
    uid: str

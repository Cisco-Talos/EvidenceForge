# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed contracts for canonical event occurrences.

The first migration stage is deliberately non-enforcing. ``shadow_seal`` takes an immutable
snapshot of the event-kind and context boundary, reports contract violations, and leaves the
legacy ``OccurrenceBuilder`` untouched so existing generation and projection remain byte-compatible.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from evidenceforge.utils.rng import stable_uuid


class EventKind(StrEnum):
    """Closed set of currently produced canonical occurrence kinds."""

    ACCOUNT_CHANGED = "account_changed"
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_DELETED = "account_deleted"
    BASH_COMMAND = "bash_command"
    CONNECTION = "connection"
    CREATE_REMOTE_THREAD = "create_remote_thread"
    DHCP_LEASE = "dhcp_lease"
    EXPLICIT_CREDENTIALS = "explicit_credentials"
    FAILED_LOGON = "failed_logon"
    FILE_CREATE = "file_create"
    FILE_DELETE = "file_delete"
    FILE_MODIFY = "file_modify"
    FILE_READ = "file_read"
    GROUP_MEMBER_ADDED_GLOBAL = "group_member_added_global"
    GROUP_MEMBER_ADDED_LOCAL = "group_member_added_local"
    GROUP_MEMBER_ADDED_UNIVERSAL = "group_member_added_universal"
    GROUP_MEMBER_REMOVED_GLOBAL = "group_member_removed_global"
    GROUP_MEMBER_REMOVED_LOCAL = "group_member_removed_local"
    GROUP_MEMBER_REMOVED_UNIVERSAL = "group_member_removed_universal"
    IMAGE_LOAD = "image_load"
    KERBEROS_PREAUTH_FAILED = "kerberos_preauth_failed"
    KERBEROS_SERVICE = "kerberos_service"
    KERBEROS_TGT = "kerberos_tgt"
    KERBEROS_TGT_RENEWAL = "kerberos_tgt_renewal"
    LOG_CLEARED = "log_cleared"
    LOGOFF = "logoff"
    LOGON = "logon"
    MACHINE_LOGON = "machine_logon"
    NTLM_VALIDATION = "ntlm_validation"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"
    PROCESS_ACCESS = "process_access"
    PROCESS_CREATE = "process_create"
    PROCESS_TERMINATE = "process_terminate"
    REGISTRY_MODIFY = "registry_modify"
    SCHEDULED_TASK_CREATED = "scheduled_task_created"
    SCHEDULED_TASK_DELETED = "scheduled_task_deleted"
    SCHEDULED_TASK_DISABLED = "scheduled_task_disabled"
    SCHEDULED_TASK_ENABLED = "scheduled_task_enabled"
    SENSOR_STARTUP = "sensor_startup"
    SERVICE_INSTALLED = "service_installed"
    SMB_DIRECTORY_ENUMERATION = "smb_directory_enumeration"
    SMB_FILE_CLOSE = "smb_file_close"
    SMB_FILE_DELETE = "smb_file_delete"
    SMB_FILE_OPEN = "smb_file_open"
    SMB_FILE_READ = "smb_file_read"
    SMB_FILE_RENAME = "smb_file_rename"
    SMB_FILE_WRITE = "smb_file_write"
    SMB_TREE_CONNECT = "smb_tree_connect"
    SSH_SESSION = "ssh_session"
    SYSLOG = "syslog"
    SYSTEM_PROCESS_CREATE = "system_process_create"
    WFP_CONNECTION = "wfp_connection"
    WORKSTATION_LOCKED = "workstation_locked"
    WORKSTATION_UNLOCKED = "workstation_unlocked"


class ContextKind(StrEnum):
    """Typed semantic context fields carried by ``OccurrenceBuilder``."""

    ACCOUNT_MANAGEMENT = "account_management"
    AUTH = "auth"
    DHCP = "dhcp"
    DNS = "dns"
    DST_HOST = "dst_host"
    EMAIL = "email"
    FILE = "file"
    FILE_TRANSFER = "file_transfer"
    FILE_TRANSFERS = "file_transfers"
    FIREWALL = "firewall"
    GROUP_MEMBERSHIP = "group_membership"
    HTTP = "http"
    IDS_ALERTS = "ids_alerts"
    IMAGE_LOAD = "image_load"
    KERBEROS = "kerberos"
    LIFECYCLE = "lifecycle"
    NAT = "nat"
    NETWORK = "network"
    NTP = "ntp"
    OCSP = "ocsp"
    OCSP_TRANSACTION = "ocsp_transaction"
    PE = "pe"
    PROCESS = "process"
    PROCESS_ACCESS = "process_access"
    PROXY = "proxy"
    REGISTRY = "registry"
    REMOTE_AUTH = "remote_auth"
    REMOTE_THREAD = "remote_thread"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    SHELL = "shell"
    SMTP = "smtp"
    SMB = "smb"
    SRC_HOST = "src_host"
    SSL = "ssl"
    SYSLOG = "syslog"
    TLS_PRESENTATION = "tls_presentation"
    WEIRD = "weird"
    X509 = "x509"
    X509_CHAIN = "x509_chain"


class FormatKind(StrEnum):
    """Closed set of concrete source projections at the reviewed baseline."""

    BASH_HISTORY = "bash_history"
    CISCO_ASA = "cisco_asa"
    ECAR = "ecar"
    PROXY_ACCESS = "proxy_access"
    SNORT_ALERT = "snort_alert"
    SYSLOG = "syslog"
    WEB_ACCESS = "web_access"
    WINDOWS_EVENT_SECURITY = "windows_event_security"
    WINDOWS_EVENT_SYSMON = "windows_event_sysmon"
    ZEEK_CONN = "zeek_conn"
    ZEEK_DHCP = "zeek_dhcp"
    ZEEK_DNS = "zeek_dns"
    ZEEK_FILES = "zeek_files"
    ZEEK_HTTP = "zeek_http"
    ZEEK_NTP = "zeek_ntp"
    ZEEK_OCSP = "zeek_ocsp"
    ZEEK_PACKET_FILTER = "zeek_packet_filter"
    ZEEK_PE = "zeek_pe"
    ZEEK_REPORTER = "zeek_reporter"
    ZEEK_SMTP = "zeek_smtp"
    ZEEK_SMB_FILES = "zeek_smb_files"
    ZEEK_SMB_MAPPING = "zeek_smb_mapping"
    ZEEK_SSL = "zeek_ssl"
    ZEEK_WEIRD = "zeek_weird"
    ZEEK_X509 = "zeek_x509"


class ProducerKind(StrEnum):
    """Current producer boundaries retained during compatibility migration."""

    ACTION_BUNDLE = "action_bundle"
    ACTIVITY_GENERATOR = "activity_generator"
    BASELINE = "baseline"
    STORYLINE = "storyline"
    CAUSAL_EXPANSION = "causal_expansion"


class HostSemantic(StrEnum):
    """Meaning of one occurrence's source or destination host field."""

    ABSENT = "absent"
    LOCAL_ACTOR = "local_actor"
    TARGET = "target"
    TRANSPORT_SOURCE = "transport_source"
    TRANSPORT_DESTINATION = "transport_destination"
    OPTIONAL = "optional"
    MIXED = "mixed"


class IdentityRequirement(StrEnum):
    """Required identity maturity for a canonical occurrence."""

    NONE = "none"
    OPTIONAL = "optional"
    REQUIRED = "required"


class LifecycleRole(StrEnum):
    """Canonical lifecycle role represented by an occurrence kind."""

    NONE = "none"
    START = "start"
    DEPENDENT = "dependent"
    CLOSURE = "closure"
    MIXED = "mixed"


class StateEffect(StrEnum):
    """High-level relationship between an occurrence and canonical state."""

    NONE = "none"
    READ = "read"
    WRITE = "write"
    MIXED = "mixed"


class OccurrenceRole(StrEnum):
    """Finite semantic role used in stable occurrence identity."""

    PRIMARY = "primary"
    PREREQUISITE = "prerequisite"
    DEPENDENT = "dependent"
    CLOSURE = "closure"
    OBSERVATION = "observation"


@dataclass(frozen=True, slots=True)
class SemanticOccurrenceKey:
    """Stable action-relative key for one occurrence.

    ``instance_key`` names the semantic instance, such as a connection UID, attempt identity,
    transfer identity, or another domain key. Positional ordinals are appropriate only for
    otherwise indistinguishable repetitions and must be scoped to their semantic peer group.
    """

    action_id: str
    role: OccurrenceRole
    instance_key: str

    def __post_init__(self) -> None:
        """Reject incomplete action-relative identity."""

        if not self.action_id:
            raise ValueError("Semantic occurrence keys require an action_id")
        if not self.instance_key:
            raise ValueError("Semantic occurrence keys require an instance_key")

    @property
    def occurrence_id(self) -> str:
        """Return the stable ID derived only from semantic action-relative parts."""

        return stable_uuid("canonical-occurrence", self.action_id, self.role, self.instance_key)


@dataclass(frozen=True, slots=True)
class EventKindContract:
    """Machine-readable legality and ownership contract for one event kind."""

    kind: EventKind
    required_contexts: frozenset[ContextKind]
    optional_contexts: frozenset[ContextKind]
    forbidden_contexts: frozenset[ContextKind]
    source_host_role: HostSemantic
    destination_host_role: HostSemantic
    identity_requirement: IdentityRequirement
    lifecycle_role: LifecycleRole
    state_effect: StateEffect
    permitted_producers: frozenset[ProducerKind]
    emitter_consumers: frozenset[FormatKind]

    def __post_init__(self) -> None:
        """Reject internally contradictory registry entries."""

        overlapping = (
            self.required_contexts & self.optional_contexts
            or self.required_contexts & self.forbidden_contexts
            or self.optional_contexts & self.forbidden_contexts
        )
        if overlapping:
            names = ", ".join(sorted(item.value for item in overlapping))
            raise ValueError(f"Event contract context sets overlap: {names}")


class ContractViolationCode(StrEnum):
    """Stable codes emitted by shadow contract validation."""

    UNKNOWN_EVENT_KIND = "unknown_event_kind"
    MISSING_CONTEXT = "missing_context"
    FORBIDDEN_CONTEXT = "forbidden_context"
    MISSING_IDENTITY = "missing_identity"


@dataclass(frozen=True, slots=True)
class ContractViolation:
    """One immutable contract discrepancy discovered during shadow sealing."""

    code: ContractViolationCode
    event_type: str
    message: str
    context: ContextKind | None = None


@dataclass(frozen=True, slots=True)
class CanonicalOccurrenceSnapshot:
    """Immutable shadow snapshot of one legacy event at the dispatch boundary."""

    kind: EventKind
    canonical_time: datetime
    present_contexts: frozenset[ContextKind]
    occurrence_key: SemanticOccurrenceKey | None


@dataclass(frozen=True, slots=True)
class ShadowSealResult:
    """Non-enforcing result of applying the canonical contract boundary."""

    occurrence: CanonicalOccurrenceSnapshot | None
    violations: tuple[ContractViolation, ...]

    @property
    def valid(self) -> bool:
        """Return whether the event satisfies the current shadow contract."""

        return not self.violations


class _EventLike(Protocol):
    """Structural event interface used to avoid a contracts/base import cycle."""

    timestamp: datetime
    event_type: str
    identity_plan: object | None
    occurrence_key: SemanticOccurrenceKey | None


_CURRENT_PRODUCERS = frozenset(ProducerKind)


def _contexts(*values: ContextKind) -> frozenset[ContextKind]:
    return frozenset(values)


def _formats(*values: FormatKind) -> frozenset[FormatKind]:
    return frozenset(values)


def _contract(
    kind: EventKind,
    *,
    required: frozenset[ContextKind],
    optional: frozenset[ContextKind] = frozenset(),
    src: HostSemantic = HostSemantic.OPTIONAL,
    dst: HostSemantic = HostSemantic.OPTIONAL,
    identity: IdentityRequirement = IdentityRequirement.OPTIONAL,
    lifecycle: LifecycleRole = LifecycleRole.NONE,
    state: StateEffect = StateEffect.NONE,
    emitters: frozenset[FormatKind] = frozenset(),
) -> EventKindContract:
    return EventKindContract(
        kind=kind,
        required_contexts=required,
        optional_contexts=optional,
        forbidden_contexts=frozenset(),
        source_host_role=src,
        destination_host_role=dst,
        identity_requirement=identity,
        lifecycle_role=lifecycle,
        state_effect=state,
        permitted_producers=_CURRENT_PRODUCERS,
        emitter_consumers=emitters,
    )


_WINDOWS_SECURITY = _formats(FormatKind.WINDOWS_EVENT_SECURITY)
_WINDOWS_ENDPOINT = _formats(
    FormatKind.ECAR,
    FormatKind.WINDOWS_EVENT_SECURITY,
    FormatKind.WINDOWS_EVENT_SYSMON,
)
_ECAR_SYSMON = _formats(FormatKind.ECAR, FormatKind.WINDOWS_EVENT_SYSMON)
_FILE_OPTIONAL = _contexts(ContextKind.AUTH, ContextKind.PROCESS)
_ACCOUNT_REQUIRED = _contexts(
    ContextKind.ACCOUNT_MANAGEMENT,
    ContextKind.AUTH,
    ContextKind.DST_HOST,
)
_GROUP_REQUIRED = _contexts(ContextKind.AUTH, ContextKind.DST_HOST, ContextKind.GROUP_MEMBERSHIP)
_KERBEROS_REQUIRED = _contexts(ContextKind.DST_HOST, ContextKind.KERBEROS)
_TASK_REQUIRED = _contexts(ContextKind.AUTH, ContextKind.SCHEDULED_TASK, ContextKind.SRC_HOST)


EVENT_KIND_CONTRACTS: dict[EventKind, EventKindContract] = {
    EventKind.ACCOUNT_CHANGED: _contract(
        EventKind.ACCOUNT_CHANGED,
        required=_ACCOUNT_REQUIRED,
        dst=HostSemantic.TARGET,
        state=StateEffect.WRITE,
        emitters=_WINDOWS_SECURITY,
    ),
    EventKind.ACCOUNT_CREATED: _contract(
        EventKind.ACCOUNT_CREATED,
        required=_ACCOUNT_REQUIRED,
        dst=HostSemantic.TARGET,
        state=StateEffect.WRITE,
        emitters=_WINDOWS_SECURITY,
    ),
    EventKind.ACCOUNT_DELETED: _contract(
        EventKind.ACCOUNT_DELETED,
        required=_ACCOUNT_REQUIRED,
        dst=HostSemantic.TARGET,
        state=StateEffect.WRITE,
        emitters=_WINDOWS_SECURITY,
    ),
    EventKind.BASH_COMMAND: _contract(
        EventKind.BASH_COMMAND,
        required=_contexts(ContextKind.AUTH, ContextKind.SHELL, ContextKind.SRC_HOST),
        src=HostSemantic.LOCAL_ACTOR,
        state=StateEffect.READ,
        emitters=_formats(FormatKind.BASH_HISTORY),
    ),
    EventKind.CONNECTION: _contract(
        EventKind.CONNECTION,
        required=_contexts(ContextKind.NETWORK),
        optional=_contexts(
            ContextKind.DNS,
            ContextKind.DST_HOST,
            ContextKind.EMAIL,
            ContextKind.FILE_TRANSFER,
            ContextKind.FILE_TRANSFERS,
            ContextKind.FIREWALL,
            ContextKind.HTTP,
            ContextKind.IDS_ALERTS,
            ContextKind.LIFECYCLE,
            ContextKind.NAT,
            ContextKind.NTP,
            ContextKind.OCSP,
            ContextKind.OCSP_TRANSACTION,
            ContextKind.PE,
            ContextKind.PROCESS,
            ContextKind.PROXY,
            ContextKind.SMTP,
            ContextKind.SRC_HOST,
            ContextKind.SSL,
            ContextKind.TLS_PRESENTATION,
            ContextKind.WEIRD,
            ContextKind.X509,
            ContextKind.X509_CHAIN,
        ),
        src=HostSemantic.TRANSPORT_SOURCE,
        dst=HostSemantic.TRANSPORT_DESTINATION,
        lifecycle=LifecycleRole.MIXED,
        state=StateEffect.WRITE,
        emitters=_formats(
            FormatKind.CISCO_ASA,
            FormatKind.ECAR,
            FormatKind.PROXY_ACCESS,
            FormatKind.SNORT_ALERT,
            FormatKind.WEB_ACCESS,
            FormatKind.WINDOWS_EVENT_SYSMON,
            FormatKind.ZEEK_CONN,
            FormatKind.ZEEK_DNS,
            FormatKind.ZEEK_FILES,
            FormatKind.ZEEK_HTTP,
            FormatKind.ZEEK_NTP,
            FormatKind.ZEEK_OCSP,
            FormatKind.ZEEK_PE,
            FormatKind.ZEEK_SMTP,
            FormatKind.ZEEK_SSL,
            FormatKind.ZEEK_WEIRD,
            FormatKind.ZEEK_X509,
        ),
    ),
    EventKind.CREATE_REMOTE_THREAD: _contract(
        EventKind.CREATE_REMOTE_THREAD,
        required=_contexts(ContextKind.PROCESS, ContextKind.REMOTE_THREAD, ContextKind.SRC_HOST),
        optional=_contexts(ContextKind.AUTH),
        src=HostSemantic.LOCAL_ACTOR,
        identity=IdentityRequirement.REQUIRED,
        lifecycle=LifecycleRole.DEPENDENT,
        state=StateEffect.WRITE,
        emitters=_ECAR_SYSMON,
    ),
    EventKind.DHCP_LEASE: _contract(
        EventKind.DHCP_LEASE,
        required=_contexts(ContextKind.DHCP, ContextKind.NETWORK, ContextKind.SRC_HOST),
        optional=_contexts(ContextKind.IDS_ALERTS),
        src=HostSemantic.LOCAL_ACTOR,
        lifecycle=LifecycleRole.MIXED,
        state=StateEffect.WRITE,
        emitters=_formats(FormatKind.ZEEK_CONN, FormatKind.ZEEK_DHCP),
    ),
    EventKind.EXPLICIT_CREDENTIALS: _contract(
        EventKind.EXPLICIT_CREDENTIALS,
        required=_contexts(ContextKind.AUTH, ContextKind.DST_HOST),
        dst=HostSemantic.TARGET,
        state=StateEffect.READ,
        emitters=_WINDOWS_SECURITY,
    ),
    EventKind.FAILED_LOGON: _contract(
        EventKind.FAILED_LOGON,
        required=_contexts(ContextKind.AUTH, ContextKind.DST_HOST),
        dst=HostSemantic.TARGET,
        state=StateEffect.READ,
        emitters=_formats(FormatKind.ECAR, FormatKind.WINDOWS_EVENT_SECURITY),
    ),
    **{
        kind: _contract(
            kind,
            required=_contexts(ContextKind.FILE, ContextKind.SRC_HOST),
            optional=_FILE_OPTIONAL,
            src=HostSemantic.LOCAL_ACTOR,
            identity=IdentityRequirement.OPTIONAL,
            lifecycle=LifecycleRole.DEPENDENT,
            state=StateEffect.READ if kind is EventKind.FILE_READ else StateEffect.WRITE,
            emitters=(
                _formats(FormatKind.ECAR, FormatKind.WINDOWS_EVENT_SYSMON)
                if kind in {EventKind.FILE_CREATE, EventKind.FILE_MODIFY}
                else _formats(FormatKind.ECAR)
            ),
        )
        for kind in (
            EventKind.FILE_CREATE,
            EventKind.FILE_DELETE,
            EventKind.FILE_MODIFY,
            EventKind.FILE_READ,
        )
    },
    **{
        kind: _contract(
            kind,
            required=_GROUP_REQUIRED,
            dst=HostSemantic.TARGET,
            state=StateEffect.WRITE,
            emitters=_WINDOWS_SECURITY,
        )
        for kind in (
            EventKind.GROUP_MEMBER_ADDED_GLOBAL,
            EventKind.GROUP_MEMBER_ADDED_LOCAL,
            EventKind.GROUP_MEMBER_ADDED_UNIVERSAL,
            EventKind.GROUP_MEMBER_REMOVED_GLOBAL,
            EventKind.GROUP_MEMBER_REMOVED_LOCAL,
            EventKind.GROUP_MEMBER_REMOVED_UNIVERSAL,
        )
    },
    EventKind.IMAGE_LOAD: _contract(
        EventKind.IMAGE_LOAD,
        required=_contexts(ContextKind.IMAGE_LOAD, ContextKind.PROCESS, ContextKind.SRC_HOST),
        optional=_contexts(ContextKind.AUTH),
        src=HostSemantic.LOCAL_ACTOR,
        identity=IdentityRequirement.REQUIRED,
        lifecycle=LifecycleRole.DEPENDENT,
        state=StateEffect.READ,
        emitters=_ECAR_SYSMON,
    ),
    **{
        kind: _contract(
            kind,
            required=_KERBEROS_REQUIRED,
            dst=HostSemantic.TARGET,
            state=StateEffect.READ,
            emitters=_WINDOWS_SECURITY,
        )
        for kind in (
            EventKind.KERBEROS_PREAUTH_FAILED,
            EventKind.KERBEROS_SERVICE,
            EventKind.KERBEROS_TGT,
            EventKind.KERBEROS_TGT_RENEWAL,
        )
    },
    EventKind.LOG_CLEARED: _contract(
        EventKind.LOG_CLEARED,
        required=_contexts(ContextKind.AUTH, ContextKind.SRC_HOST),
        src=HostSemantic.LOCAL_ACTOR,
        state=StateEffect.WRITE,
        emitters=_WINDOWS_SECURITY,
    ),
    EventKind.LOGOFF: _contract(
        EventKind.LOGOFF,
        required=_contexts(ContextKind.AUTH, ContextKind.DST_HOST),
        optional=_contexts(ContextKind.LIFECYCLE, ContextKind.SYSLOG),
        dst=HostSemantic.TARGET,
        identity=IdentityRequirement.REQUIRED,
        lifecycle=LifecycleRole.CLOSURE,
        state=StateEffect.WRITE,
        emitters=_formats(FormatKind.ECAR, FormatKind.WINDOWS_EVENT_SECURITY),
    ),
    EventKind.LOGON: _contract(
        EventKind.LOGON,
        required=_contexts(ContextKind.AUTH, ContextKind.DST_HOST),
        optional=_contexts(
            ContextKind.LIFECYCLE,
            ContextKind.REMOTE_AUTH,
            ContextKind.SRC_HOST,
        ),
        src=HostSemantic.OPTIONAL,
        dst=HostSemantic.TARGET,
        identity=IdentityRequirement.REQUIRED,
        lifecycle=LifecycleRole.START,
        state=StateEffect.WRITE,
        emitters=_formats(FormatKind.ECAR, FormatKind.WINDOWS_EVENT_SECURITY),
    ),
    EventKind.MACHINE_LOGON: _contract(
        EventKind.MACHINE_LOGON,
        required=_contexts(ContextKind.AUTH, ContextKind.DST_HOST),
        optional=_contexts(ContextKind.LIFECYCLE, ContextKind.REMOTE_AUTH),
        dst=HostSemantic.TARGET,
        identity=IdentityRequirement.REQUIRED,
        lifecycle=LifecycleRole.START,
        state=StateEffect.WRITE,
        emitters=_formats(FormatKind.ECAR, FormatKind.WINDOWS_EVENT_SECURITY),
    ),
    EventKind.NTLM_VALIDATION: _contract(
        EventKind.NTLM_VALIDATION,
        required=_contexts(ContextKind.AUTH, ContextKind.DST_HOST),
        dst=HostSemantic.TARGET,
        state=StateEffect.READ,
        emitters=_WINDOWS_SECURITY,
    ),
    **{
        kind: _contract(
            kind,
            required=_contexts(ContextKind.NETWORK, ContextKind.SMB),
            optional=_contexts(
                ContextKind.AUTH,
                ContextKind.DST_HOST,
                ContextKind.FILE,
                ContextKind.FILE_TRANSFER,
                ContextKind.FILE_TRANSFERS,
                ContextKind.LIFECYCLE,
                ContextKind.PROCESS,
                ContextKind.SRC_HOST,
            ),
            src=HostSemantic.TRANSPORT_SOURCE,
            dst=HostSemantic.TRANSPORT_DESTINATION,
            lifecycle=LifecycleRole.DEPENDENT,
            state=(
                StateEffect.READ
                if kind
                in {
                    EventKind.SMB_DIRECTORY_ENUMERATION,
                    EventKind.SMB_FILE_OPEN,
                    EventKind.SMB_FILE_READ,
                }
                else StateEffect.WRITE
                if kind
                in {
                    EventKind.SMB_FILE_WRITE,
                    EventKind.SMB_FILE_RENAME,
                    EventKind.SMB_FILE_DELETE,
                }
                else StateEffect.NONE
            ),
            emitters=_formats(
                FormatKind.ECAR,
                FormatKind.WINDOWS_EVENT_SECURITY,
                FormatKind.ZEEK_FILES,
                FormatKind.ZEEK_SMB_FILES,
                FormatKind.ZEEK_SMB_MAPPING,
            ),
        )
        for kind in (
            EventKind.SMB_TREE_CONNECT,
            EventKind.SMB_DIRECTORY_ENUMERATION,
            EventKind.SMB_FILE_OPEN,
            EventKind.SMB_FILE_READ,
            EventKind.SMB_FILE_WRITE,
            EventKind.SMB_FILE_RENAME,
            EventKind.SMB_FILE_DELETE,
            EventKind.SMB_FILE_CLOSE,
        )
    },
    EventKind.PASSWORD_CHANGE: _contract(
        EventKind.PASSWORD_CHANGE,
        required=_ACCOUNT_REQUIRED,
        dst=HostSemantic.TARGET,
        state=StateEffect.WRITE,
        emitters=_WINDOWS_SECURITY,
    ),
    EventKind.PASSWORD_RESET: _contract(
        EventKind.PASSWORD_RESET,
        required=_ACCOUNT_REQUIRED,
        dst=HostSemantic.TARGET,
        state=StateEffect.WRITE,
        emitters=_WINDOWS_SECURITY,
    ),
    EventKind.PROCESS_ACCESS: _contract(
        EventKind.PROCESS_ACCESS,
        required=_contexts(ContextKind.PROCESS, ContextKind.PROCESS_ACCESS, ContextKind.SRC_HOST),
        optional=_contexts(ContextKind.AUTH),
        src=HostSemantic.LOCAL_ACTOR,
        identity=IdentityRequirement.REQUIRED,
        lifecycle=LifecycleRole.DEPENDENT,
        state=StateEffect.READ,
        emitters=_ECAR_SYSMON,
    ),
    EventKind.PROCESS_CREATE: _contract(
        EventKind.PROCESS_CREATE,
        required=_contexts(ContextKind.PROCESS, ContextKind.SRC_HOST),
        optional=_contexts(ContextKind.AUTH),
        src=HostSemantic.LOCAL_ACTOR,
        identity=IdentityRequirement.REQUIRED,
        lifecycle=LifecycleRole.START,
        state=StateEffect.WRITE,
        emitters=_WINDOWS_ENDPOINT,
    ),
    EventKind.PROCESS_TERMINATE: _contract(
        EventKind.PROCESS_TERMINATE,
        required=_contexts(ContextKind.PROCESS, ContextKind.SRC_HOST),
        optional=_contexts(ContextKind.AUTH),
        src=HostSemantic.LOCAL_ACTOR,
        identity=IdentityRequirement.REQUIRED,
        lifecycle=LifecycleRole.CLOSURE,
        state=StateEffect.WRITE,
        emitters=_WINDOWS_ENDPOINT,
    ),
    EventKind.REGISTRY_MODIFY: _contract(
        EventKind.REGISTRY_MODIFY,
        required=_contexts(ContextKind.PROCESS, ContextKind.REGISTRY, ContextKind.SRC_HOST),
        optional=_contexts(ContextKind.AUTH),
        src=HostSemantic.LOCAL_ACTOR,
        identity=IdentityRequirement.OPTIONAL,
        lifecycle=LifecycleRole.DEPENDENT,
        state=StateEffect.WRITE,
        emitters=_ECAR_SYSMON,
    ),
    **{
        kind: _contract(
            kind,
            required=_TASK_REQUIRED,
            src=HostSemantic.LOCAL_ACTOR,
            state=StateEffect.WRITE,
            emitters=_WINDOWS_SECURITY,
        )
        for kind in (
            EventKind.SCHEDULED_TASK_CREATED,
            EventKind.SCHEDULED_TASK_DELETED,
            EventKind.SCHEDULED_TASK_DISABLED,
            EventKind.SCHEDULED_TASK_ENABLED,
        )
    },
    EventKind.SENSOR_STARTUP: _contract(
        EventKind.SENSOR_STARTUP,
        required=_contexts(ContextKind.SRC_HOST),
        optional=_contexts(ContextKind.SHELL),
        src=HostSemantic.LOCAL_ACTOR,
        state=StateEffect.NONE,
        emitters=_formats(FormatKind.ZEEK_PACKET_FILTER, FormatKind.ZEEK_REPORTER),
    ),
    EventKind.SERVICE_INSTALLED: _contract(
        EventKind.SERVICE_INSTALLED,
        required=_contexts(ContextKind.AUTH, ContextKind.SERVICE, ContextKind.SRC_HOST),
        src=HostSemantic.LOCAL_ACTOR,
        state=StateEffect.WRITE,
        emitters=_formats(FormatKind.ECAR, FormatKind.WINDOWS_EVENT_SECURITY),
    ),
    EventKind.SSH_SESSION: _contract(
        EventKind.SSH_SESSION,
        required=_contexts(ContextKind.AUTH, ContextKind.DST_HOST),
        optional=_contexts(ContextKind.PROCESS, ContextKind.SRC_HOST),
        src=HostSemantic.TRANSPORT_SOURCE,
        dst=HostSemantic.TARGET,
        identity=IdentityRequirement.REQUIRED,
        lifecycle=LifecycleRole.START,
        state=StateEffect.WRITE,
        emitters=_formats(FormatKind.ECAR),
    ),
    EventKind.SYSLOG: _contract(
        EventKind.SYSLOG,
        required=_contexts(ContextKind.SRC_HOST, ContextKind.SYSLOG),
        optional=_contexts(ContextKind.AUTH),
        src=HostSemantic.LOCAL_ACTOR,
        state=StateEffect.NONE,
        emitters=_formats(FormatKind.SYSLOG),
    ),
    EventKind.SYSTEM_PROCESS_CREATE: _contract(
        EventKind.SYSTEM_PROCESS_CREATE,
        required=_contexts(ContextKind.PROCESS, ContextKind.SRC_HOST),
        optional=_contexts(ContextKind.AUTH),
        src=HostSemantic.LOCAL_ACTOR,
        identity=IdentityRequirement.REQUIRED,
        lifecycle=LifecycleRole.START,
        state=StateEffect.WRITE,
        emitters=_WINDOWS_ENDPOINT,
    ),
    EventKind.WFP_CONNECTION: _contract(
        EventKind.WFP_CONNECTION,
        required=_contexts(ContextKind.NETWORK, ContextKind.SRC_HOST),
        optional=_contexts(ContextKind.LIFECYCLE, ContextKind.PROCESS),
        src=HostSemantic.TRANSPORT_SOURCE,
        dst=HostSemantic.TRANSPORT_DESTINATION,
        lifecycle=LifecycleRole.DEPENDENT,
        state=StateEffect.READ,
        emitters=_WINDOWS_SECURITY,
    ),
    EventKind.WORKSTATION_LOCKED: _contract(
        EventKind.WORKSTATION_LOCKED,
        required=_contexts(ContextKind.AUTH, ContextKind.DST_HOST),
        dst=HostSemantic.TARGET,
        state=StateEffect.WRITE,
        emitters=_WINDOWS_SECURITY,
    ),
    EventKind.WORKSTATION_UNLOCKED: _contract(
        EventKind.WORKSTATION_UNLOCKED,
        required=_contexts(ContextKind.AUTH, ContextKind.DST_HOST),
        dst=HostSemantic.TARGET,
        state=StateEffect.WRITE,
        emitters=_WINDOWS_SECURITY,
    ),
}


def contract_for(event_type: str) -> EventKindContract | None:
    """Return the registered contract for an event type, if it is canonical."""

    try:
        kind = EventKind(event_type)
    except ValueError:
        return None
    return EVENT_KIND_CONTRACTS[kind]


def _present_contexts(event: _EventLike) -> frozenset[ContextKind]:
    present: set[ContextKind] = set()
    for context in ContextKind:
        value = getattr(event, context.value, None)
        if value is None or value == () or value == []:
            continue
        present.add(context)
    return frozenset(present)


def shadow_seal(event: _EventLike) -> ShadowSealResult:
    """Build an immutable occurrence snapshot and report, but do not enforce, violations."""

    contract = contract_for(event.event_type)
    if contract is None:
        violation = ContractViolation(
            code=ContractViolationCode.UNKNOWN_EVENT_KIND,
            event_type=event.event_type,
            message=f"Unknown canonical event kind: {event.event_type}",
        )
        return ShadowSealResult(occurrence=None, violations=(violation,))

    present = _present_contexts(event)
    violations: list[ContractViolation] = []
    for context in sorted(contract.required_contexts - present, key=lambda item: item.value):
        violations.append(
            ContractViolation(
                code=ContractViolationCode.MISSING_CONTEXT,
                event_type=event.event_type,
                context=context,
                message=f"{event.event_type} requires context '{context.value}'",
            )
        )
    for context in sorted(contract.forbidden_contexts & present, key=lambda item: item.value):
        violations.append(
            ContractViolation(
                code=ContractViolationCode.FORBIDDEN_CONTEXT,
                event_type=event.event_type,
                context=context,
                message=f"{event.event_type} forbids context '{context.value}'",
            )
        )
    if (
        contract.identity_requirement is IdentityRequirement.REQUIRED
        and event.identity_plan is None
    ):
        violations.append(
            ContractViolation(
                code=ContractViolationCode.MISSING_IDENTITY,
                event_type=event.event_type,
                message=f"{event.event_type} requires a canonical identity plan",
            )
        )

    occurrence = CanonicalOccurrenceSnapshot(
        kind=contract.kind,
        canonical_time=event.timestamp,
        present_contexts=present,
        occurrence_key=event.occurrence_key,
    )
    return ShadowSealResult(occurrence=occurrence, violations=tuple(violations))


def assert_registry_closed() -> None:
    """Raise if the registry is missing or contains an unexpected canonical kind."""

    registered = set(EVENT_KIND_CONTRACTS)
    expected = set(EventKind)
    if registered != expected:
        missing = sorted(kind.value for kind in expected - registered)
        unexpected = sorted(kind.value for kind in registered - expected)
        raise AssertionError(
            f"Canonical event registry is not closed; missing={missing}, unexpected={unexpected}"
        )


assert_registry_closed()

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical behavior-to-evidence reachability contracts.

Behavior producers own what counts as an acceptable evidence projection. Validators and runtime
guards consume these immutable contracts so neither layer invents a private format allowlist.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from evidenceforge.events.collection_policy import CollectionCapability
from evidenceforge.events.contracts import EVENT_KIND_CONTRACTS, EventKind, FormatKind


class EvidenceReachabilitySeverity(StrEnum):
    """Consequence when no configured source can satisfy a behavior contract."""

    ERROR = "error"
    WARNING = "warning"


class EvidenceSourceScope(StrEnum):
    """Source owners eligible to satisfy one behavior projection."""

    ANY = "any"
    TARGET_HOST = "target_host"
    PARTICIPANT_OR_SENSOR = "participant_or_sensor"


@dataclass(frozen=True, slots=True)
class EvidenceProjectionAlternative:
    """One acceptable source-format and capability alternative."""

    formats: frozenset[str]
    capabilities: CollectionCapability = CollectionCapability.NONE

    def __post_init__(self) -> None:
        """Normalize format names and reject an empty alternative."""

        formats = frozenset(format_name.strip().casefold() for format_name in self.formats)
        if not formats or "" in formats:
            raise ValueError("evidence projection alternatives require concrete source formats")
        object.__setattr__(self, "formats", formats)
        object.__setattr__(self, "capabilities", CollectionCapability(self.capabilities))


@dataclass(frozen=True, slots=True)
class BehaviorEvidenceContract:
    """Minimum source evidence required for one configured behavior family."""

    behavior_id: str
    label: str
    alternatives: tuple[EvidenceProjectionAlternative, ...]
    source_scope: EvidenceSourceScope
    unreachable_severity: EvidenceReachabilitySeverity
    suggestion: str

    def __post_init__(self) -> None:
        """Normalize identity and reject incomplete contracts."""

        behavior_id = self.behavior_id.strip().casefold()
        label = self.label.strip()
        suggestion = self.suggestion.strip()
        alternatives = tuple(self.alternatives)
        if not behavior_id or not label or not suggestion or not alternatives:
            raise ValueError("behavior evidence contracts require identity, guidance, and routes")
        object.__setattr__(self, "behavior_id", behavior_id)
        object.__setattr__(self, "label", label)
        object.__setattr__(self, "alternatives", alternatives)
        object.__setattr__(self, "source_scope", EvidenceSourceScope(self.source_scope))
        object.__setattr__(
            self,
            "unreachable_severity",
            EvidenceReachabilitySeverity(self.unreachable_severity),
        )
        object.__setattr__(self, "suggestion", suggestion)

    @property
    def format_names(self) -> tuple[str, ...]:
        """Return every acceptable concrete format in deterministic order."""

        return tuple(
            sorted({name for alternative in self.alternatives for name in alternative.formats})
        )


def _event_contract(
    *,
    behavior_id: str,
    label: str,
    event_kind: EventKind,
    capabilities: CollectionCapability,
    suggestion: str,
    source_scope: EvidenceSourceScope = EvidenceSourceScope.TARGET_HOST,
) -> BehaviorEvidenceContract:
    consumers = EVENT_KIND_CONTRACTS[event_kind].emitter_consumers
    return BehaviorEvidenceContract(
        behavior_id=behavior_id,
        label=label,
        alternatives=(
            EvidenceProjectionAlternative(
                formats=frozenset(format_kind.value for format_kind in consumers),
                capabilities=capabilities,
            ),
        ),
        source_scope=source_scope,
        unreachable_severity=EvidenceReachabilitySeverity.WARNING,
        suggestion=suggestion,
    )


PERSISTENT_WINDOWS_SMB_EVIDENCE = BehaviorEvidenceContract(
    behavior_id="persistent_windows_smb",
    label="persistent Windows SMB activity",
    alternatives=(
        EvidenceProjectionAlternative(
            formats=frozenset({FormatKind.ZEEK_CONN.value}),
            capabilities=CollectionCapability.NETWORK,
        ),
        EvidenceProjectionAlternative(
            formats=frozenset({FormatKind.ZEEK_SMB_MAPPING.value}),
            capabilities=CollectionCapability.SMB,
        ),
        EvidenceProjectionAlternative(
            formats=frozenset({FormatKind.ZEEK_SMB_FILES.value}),
            capabilities=CollectionCapability.SMB,
        ),
        EvidenceProjectionAlternative(
            formats=frozenset({FormatKind.ZEEK_FILES.value}),
            capabilities=CollectionCapability.FILE,
        ),
        EvidenceProjectionAlternative(
            formats=frozenset({FormatKind.ECAR.value}),
            capabilities=CollectionCapability.SMB,
        ),
        EvidenceProjectionAlternative(
            formats=frozenset({FormatKind.WINDOWS_EVENT_SECURITY.value}),
            capabilities=CollectionCapability.SMB,
        ),
    ),
    source_scope=EvidenceSourceScope.PARTICIPANT_OR_SENSOR,
    unreachable_severity=EvidenceReachabilitySeverity.ERROR,
    suggestion=(
        "Enable the windows, ecar, or applicable Zeek output sources, or remove the Windows SMB "
        "behavior from the environment/storyline."
    ),
)

PERSISTENT_WINDOWS_SMB_TARGET_FORMATS = tuple(
    next(iter(alternative.formats)) for alternative in PERSISTENT_WINDOWS_SMB_EVIDENCE.alternatives
)


def _host_event_contracts() -> dict[str, BehaviorEvidenceContract]:
    process_guidance = "Enable ecar or the applicable Windows endpoint format."
    security_guidance = "Enable windows_event_security (or the windows output group)."
    return {
        "process": _event_contract(
            behavior_id="authored_process",
            label="authored process execution",
            event_kind=EventKind.PROCESS_CREATE,
            capabilities=CollectionCapability.PROCESS,
            suggestion=process_guidance,
        ),
        "create_remote_thread": _event_contract(
            behavior_id="authored_remote_thread",
            label="authored remote-thread creation",
            event_kind=EventKind.CREATE_REMOTE_THREAD,
            capabilities=CollectionCapability.PROCESS,
            suggestion="Enable ecar or windows_event_sysmon.",
        ),
        "process_access": _event_contract(
            behavior_id="authored_process_access",
            label="authored process access",
            event_kind=EventKind.PROCESS_ACCESS,
            capabilities=CollectionCapability.PROCESS,
            suggestion="Enable ecar or windows_event_sysmon.",
        ),
        "account_created": _event_contract(
            behavior_id="authored_account_creation",
            label="authored account creation",
            event_kind=EventKind.ACCOUNT_CREATED,
            capabilities=CollectionCapability.ACCOUNT,
            suggestion=security_guidance,
        ),
        "account_deleted": _event_contract(
            behavior_id="authored_account_deletion",
            label="authored account deletion",
            event_kind=EventKind.ACCOUNT_DELETED,
            capabilities=CollectionCapability.ACCOUNT,
            suggestion=security_guidance,
        ),
        "group_member_added": _event_contract(
            behavior_id="authored_group_membership",
            label="authored group membership change",
            event_kind=EventKind.GROUP_MEMBER_ADDED_GLOBAL,
            capabilities=CollectionCapability.ACCOUNT,
            suggestion=security_guidance,
        ),
        "service_installed": _event_contract(
            behavior_id="authored_service_install",
            label="authored service installation",
            event_kind=EventKind.SERVICE_INSTALLED,
            capabilities=CollectionCapability.SERVICE,
            suggestion="Enable ecar or windows_event_security.",
        ),
        "scheduled_task_created": _event_contract(
            behavior_id="authored_scheduled_task",
            label="authored scheduled-task creation",
            event_kind=EventKind.SCHEDULED_TASK_CREATED,
            capabilities=CollectionCapability.TASK,
            suggestion=security_guidance,
        ),
        "log_cleared": _event_contract(
            behavior_id="authored_log_clear",
            label="authored Windows log clear",
            event_kind=EventKind.LOG_CLEARED,
            capabilities=CollectionCapability.AUTHENTICATION,
            suggestion=security_guidance,
        ),
        "explicit_credentials": _event_contract(
            behavior_id="authored_explicit_credentials",
            label="authored explicit credential use",
            event_kind=EventKind.EXPLICIT_CREDENTIALS,
            capabilities=CollectionCapability.AUTHENTICATION,
            suggestion=security_guidance,
        ),
        "workstation_lock": _event_contract(
            behavior_id="authored_workstation_lock",
            label="authored workstation lock",
            event_kind=EventKind.WORKSTATION_LOCKED,
            capabilities=CollectionCapability.SESSION,
            suggestion=security_guidance,
        ),
        "workstation_unlock": _event_contract(
            behavior_id="authored_workstation_unlock",
            label="authored workstation unlock",
            event_kind=EventKind.WORKSTATION_UNLOCKED,
            capabilities=CollectionCapability.SESSION,
            suggestion=security_guidance,
        ),
        "dhcp_lease": _event_contract(
            behavior_id="authored_dhcp_lease",
            label="authored DHCP lease",
            event_kind=EventKind.DHCP_LEASE,
            capabilities=CollectionCapability.NETWORK,
            suggestion="Enable applicable zeek_conn or zeek_dhcp sensor output.",
            source_scope=EvidenceSourceScope.ANY,
        ),
    }


AUTHORED_EVENT_EVIDENCE_CONTRACTS: Mapping[str, BehaviorEvidenceContract] = MappingProxyType(
    _host_event_contracts()
)

BEHAVIOR_EVIDENCE_CONTRACTS: Mapping[str, BehaviorEvidenceContract] = MappingProxyType(
    {
        PERSISTENT_WINDOWS_SMB_EVIDENCE.behavior_id: PERSISTENT_WINDOWS_SMB_EVIDENCE,
        **{
            contract.behavior_id: contract
            for contract in AUTHORED_EVENT_EVIDENCE_CONTRACTS.values()
        },
    }
)


__all__ = [
    "AUTHORED_EVENT_EVIDENCE_CONTRACTS",
    "BEHAVIOR_EVIDENCE_CONTRACTS",
    "PERSISTENT_WINDOWS_SMB_EVIDENCE",
    "PERSISTENT_WINDOWS_SMB_TARGET_FORMATS",
    "BehaviorEvidenceContract",
    "EvidenceProjectionAlternative",
    "EvidenceReachabilitySeverity",
    "EvidenceSourceScope",
]

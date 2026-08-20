# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded retention and commit handoff for persistent-SMB projection facts.

The authority retains one immutable primitive capsule and one exact detached
source-timing binding per member, plus bounded authenticated certification and
commit carriers. It never retains a prepared dispatch, source-timing
preparation, canonical occurrence graph, manager, emitter, or callback.

Lifecycle, network, and traffic binding digests are coordinator-derived scalar
facts. This layer cross-binds but deliberately does not authenticate those
external owners. A member commit receipt proves only retained member, timing,
owner-binding, topology-generation, and closed target-intent agreement. It is
not evidence that source bytes were emitted; the future production coordinator
must authenticate exact publication before acknowledging the durable handoff.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from threading import Lock
from weakref import ReferenceType, ref

from evidenceforge.generation.source_timing import (
    SourceTimingDetachedPreparationBinding,
    SourceTimingPlanner,
    SourceTimingPreparation,
    SourceTimingPreparationReceipt,
    SourceTimingPreparationToken,
)
from evidenceforge.models.exceptions import EventContractError, StateError

_MAX_OPERATION_ID_UTF8_BYTES = 512
_MAX_PROJECTION_CAPSULE_BYTES = 4 * 1024 * 1024
_MAX_CAPSULE_PARTS = 16_384
_MAX_TARGET_FORMATS = 6
_MAX_TARGET_FORMAT_UTF8_BYTES = 128
_GROUP_RETAINED_BASE_BYTES = 768
_MEMBER_RETAINED_BASE_BYTES = 1_024
_MAX_SIGNED_63 = (1 << 63) - 1


class PersistentSmbProjectionPhase(StrEnum):
    """Stable lifecycle ordering class retained with one detached member."""

    TRANSPORT = "transport"
    TYPE3_LOGON = "type3_logon"
    TREE_OR_FILE = "tree_or_file"
    TREE_DISCONNECT = "tree_disconnect"
    LOGOFF = "logoff"


def _frame(*values: bytes) -> bytes:
    """Frame exact byte fields without repr or delimiter ambiguity."""

    return b"".join(len(value).to_bytes(8, "big") + value for value in values)


def _sha256_hex(value: object, field_name: str) -> str:
    """Validate one exact lowercase SHA-256 digest."""

    if type(value) is not str or len(value) != 64:
        raise EventContractError(f"{field_name} must be one exact SHA-256 digest")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise EventContractError(f"{field_name} must be one exact SHA-256 digest") from error
    if any(byte not in b"0123456789abcdef" for byte in encoded):
        raise EventContractError(f"{field_name} must be one exact SHA-256 digest")
    return value


def _bounded_text(value: object, field_name: str, maximum: int) -> str:
    """Validate one exact non-empty bounded UTF-8 scalar without coercion."""

    if type(value) is not str or not value:
        raise EventContractError(f"{field_name} must be one non-empty exact string")
    if len(value) > maximum:
        raise EventContractError(f"{field_name} exceeds {maximum} retained UTF-8 bytes")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise EventContractError(f"{field_name} must contain valid UTF-8 text") from error
    if len(encoded) > maximum:
        raise EventContractError(f"{field_name} exceeds {maximum} retained UTF-8 bytes")
    return value


def _positive_int(value: object, field_name: str) -> int:
    """Validate one exact positive signed-63-bit scalar."""

    if type(value) is not int:
        raise EventContractError(f"{field_name} must be one positive exact int")
    if value < 1 or value > _MAX_SIGNED_63:
        raise EventContractError(f"{field_name} must fit the positive signed 63-bit range")
    return value


def _target_formats(value: object) -> tuple[str, ...]:
    """Validate one bounded canonical exact target tuple without sorting callbacks."""

    if type(value) is not tuple:
        raise EventContractError("Persistent SMB target formats require an exact tuple")
    if not value or len(value) > _MAX_TARGET_FORMATS:
        raise EventContractError("Persistent SMB target formats must fit their non-empty bound")
    checked: list[str] = []
    seen: set[str] = set()
    for item in value:
        target = _bounded_text(
            item,
            "persistent SMB target format",
            _MAX_TARGET_FORMAT_UTF8_BYTES,
        )
        if target in seen:
            raise EventContractError("Persistent SMB target formats must be unique")
        seen.add(target)
        checked.append(target)
    return tuple(checked)


def _random_hex(octets: int, field_name: str) -> str:
    """Return one exact bounded random scalar from the trusted RNG."""

    value = secrets.token_hex(octets)
    expected_length = octets * 2
    if type(value) is not str or len(value) != expected_length:
        raise EventContractError(f"{field_name} generation returned a malformed scalar")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise EventContractError(f"{field_name} generation returned a malformed scalar") from error
    if any(byte not in b"0123456789abcdef" for byte in encoded):
        raise EventContractError(f"{field_name} generation returned a malformed scalar")
    return value


def encode_persistent_smb_projection_capsule(parts: tuple[bytes, ...]) -> bytes:
    """Encode bounded exact primitive fields into one immutable capsule.

    This is intentionally not a generic serializer. Mappings, iterators,
    objects, bytearray instances, subclasses, and conversion callbacks are
    rejected.
    """

    if type(parts) is not tuple:
        raise EventContractError("Persistent SMB projection capsule parts require an exact tuple")
    if len(parts) > _MAX_CAPSULE_PARTS:
        raise EventContractError("Persistent SMB projection capsule has too many primitive parts")
    version = b"persistent-smb-projection-capsule-v1"
    total = 8 + len(version)
    checked: list[bytes] = []
    for ordinal, part in enumerate(parts):
        if type(part) is not bytes:
            raise EventContractError(
                f"Persistent SMB projection capsule part {ordinal} requires exact bytes"
            )
        total += 8 + len(part)
        if total > _MAX_PROJECTION_CAPSULE_BYTES:
            raise EventContractError("Persistent SMB projection capsule exceeds its byte bound")
        checked.append(part)
    return _frame(version, *checked)


@dataclass(frozen=True, slots=True)
class PersistentSmbProjectionGroupToken:
    """Exact dispatcher-issued ownership token for one open detached group."""

    dispatcher_id: str
    group_id: int
    generation_id: str
    projection_configuration_digest: str
    member_budget: int
    byte_budget: int
    _integrity: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class PersistentSmbProjectionMemberToken:
    """Exact token for one precharged inactive detached member."""

    dispatcher_id: str
    group_id: int
    generation_id: str
    member_id: int
    member_ordinal: int
    phase: PersistentSmbProjectionPhase
    operation_id: str
    operation_binding_digest: str
    projection_configuration_digest: str
    capsule_digest: str
    timing_context_digest: str
    timing_binding: SourceTimingDetachedPreparationBinding
    retained_bytes: int
    _integrity: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class PersistentSmbProjectionMemberRecovery:
    """O(1) exact same-operation inactive reconciliation result."""

    member_token: PersistentSmbProjectionMemberToken
    state: str


@dataclass(frozen=True, slots=True)
class PersistentSmbProjectionMemberCertification:
    """Exact authority-issued claim over one inactive member and target intent."""

    dispatcher_id: str
    group_id: int
    generation_id: str
    member_id: int
    member_ordinal: int
    phase: PersistentSmbProjectionPhase
    operation_id: str
    operation_binding_digest: str
    capsule_digest: str
    timing_context_digest: str
    timing_receipt_digest: str
    topology_generation_digest: str
    target_formats: tuple[str, ...]
    lifecycle_binding_digest: str
    lifecycle_binding_generation: int
    network_binding_digest: str
    network_binding_generation: int
    traffic_binding_digest: str
    traffic_binding_generation: int
    expected_timing_receipt: SourceTimingPreparationReceipt = field(repr=False)
    _integrity: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class PersistentSmbProjectionMemberCommitReceipt:
    """Authenticated committed-but-unacknowledged member handoff receipt."""

    dispatcher_id: str
    group_id: int
    generation_id: str
    member_id: int
    member_ordinal: int
    phase: PersistentSmbProjectionPhase
    operation_id: str
    operation_binding_digest: str
    capsule_digest: str
    timing_context_digest: str
    timing_receipt_digest: str
    topology_generation_digest: str
    target_formats: tuple[str, ...]
    lifecycle_binding_digest: str
    lifecycle_binding_generation: int
    network_binding_digest: str
    network_binding_generation: int
    traffic_binding_digest: str
    traffic_binding_generation: int
    state: str
    _integrity: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class PersistentSmbProjectionCommittedMemberRecovery:
    """O(1) exact same-operation committed lost-return recovery result."""

    commit_receipt: PersistentSmbProjectionMemberCommitReceipt
    state: str


@dataclass(frozen=True, slots=True)
class PersistentSmbProjectionGroupCensus:
    """Constant-time live-retention and declared-reservation accounting."""

    retained_groups: int
    inactive_members: int
    certified_members: int
    committed_unacknowledged_members: int
    retained_commit_receipts: int
    retained_bytes: int
    reserved_member_capacity: int
    reserved_receipt_capacity: int
    reserved_byte_capacity: int
    group_capacity: int
    member_capacity: int
    receipt_capacity: int
    byte_capacity: int
    high_water_groups: int
    high_water_members: int
    high_water_certified_members: int
    high_water_committed_unacknowledged_members: int
    high_water_commit_receipts: int
    high_water_bytes: int
    high_water_table_backing_bytes: int
    retained_target_generations: int
    target_generation_capacity: int
    high_water_target_generations: int
    target_generation_semantic_bytes: int
    target_generation_table_backing_bytes: int
    high_water_target_generation_table_backing_bytes: int
    entry_semantic_bytes: int
    table_backing_bytes: int
    estimated_bytes: int


@dataclass(frozen=True, slots=True)
class _PersistentSmbGroupFacts:
    dispatcher_id: str
    group_id: int
    generation_id: str
    projection_configuration_digest: str
    member_budget: int
    byte_budget: int
    integrity: str


@dataclass(frozen=True, slots=True)
class _PersistentSmbTimingFacts:
    binding_id: str
    preparation_id: int
    base_state_digest: str
    overlay_digest: str
    context_digest: str
    integrity: str


@dataclass(frozen=True, slots=True)
class _PersistentSmbMemberReservation:
    group_id: int
    member_id: int
    member_ordinal: int
    phase: PersistentSmbProjectionPhase
    operation_id: str
    operation_binding_digest: str
    capsule_digest: str
    retained_bytes: int


@dataclass(frozen=True, slots=True)
class _PersistentSmbMemberFacts:
    dispatcher_id: str
    group_id: int
    generation_id: str
    member_id: int
    member_ordinal: int
    phase: PersistentSmbProjectionPhase
    operation_id: str
    operation_binding_digest: str
    projection_configuration_digest: str
    capsule_digest: str
    timing_context_digest: str
    timing: _PersistentSmbTimingFacts
    retained_bytes: int
    integrity: str


@dataclass(frozen=True, slots=True)
class _PersistentSmbCertificationFacts:
    dispatcher_id: str
    group_id: int
    generation_id: str
    member_id: int
    member_ordinal: int
    phase: PersistentSmbProjectionPhase
    operation_id: str
    operation_binding_digest: str
    capsule_digest: str
    timing_context_digest: str
    timing_receipt_digest: str
    topology_generation_digest: str
    target_formats: tuple[str, ...]
    lifecycle_binding_digest: str
    lifecycle_binding_generation: int
    network_binding_digest: str
    network_binding_generation: int
    traffic_binding_digest: str
    traffic_binding_generation: int
    expected_timing_receipt: SourceTimingPreparationReceipt
    integrity: str


@dataclass(frozen=True, slots=True)
class _PersistentSmbCommitReceiptFacts:
    dispatcher_id: str
    group_id: int
    generation_id: str
    member_id: int
    member_ordinal: int
    phase: PersistentSmbProjectionPhase
    operation_id: str
    operation_binding_digest: str
    capsule_digest: str
    timing_context_digest: str
    timing_receipt_digest: str
    topology_generation_digest: str
    target_formats: tuple[str, ...]
    lifecycle_binding_digest: str
    lifecycle_binding_generation: int
    network_binding_digest: str
    network_binding_generation: int
    traffic_binding_digest: str
    traffic_binding_generation: int
    state: str
    integrity: str


@dataclass(slots=True)
class _PersistentSmbMemberRecord:
    token: PersistentSmbProjectionMemberToken | None
    capsule: bytes | None
    operation_id: str
    operation_binding_digest: str
    capsule_digest: str
    retained_bytes: int
    reservation: _PersistentSmbMemberReservation
    facts: _PersistentSmbMemberFacts | None = None
    timing_binding: SourceTimingDetachedPreparationBinding | None = None
    timing_owner_ref: ReferenceType[SourceTimingPlanner] | None = None
    certification: PersistentSmbProjectionMemberCertification | None = None
    expected_timing_receipt: SourceTimingPreparationReceipt | None = None
    commit_receipt: PersistentSmbProjectionMemberCommitReceipt | None = None
    state: str = "preparing"


@dataclass(slots=True)
class _PersistentSmbGroupRecord:
    owner_ref: ReferenceType[PersistentSmbProjectionGroupAuthority]
    token: PersistentSmbProjectionGroupToken
    facts: _PersistentSmbGroupFacts
    base_retained_bytes: int
    retained_bytes: int
    member_bytes: int = 0
    next_member_id: int = 1
    next_member_ordinal: int = 0
    members: dict[int, _PersistentSmbMemberRecord] = field(default_factory=dict)
    member_by_operation: dict[str, int] = field(default_factory=dict)
    state: str = "open"


class PersistentSmbProjectionGroupAuthority:
    """Own bounded groups containing only inactive detached members."""

    def __init__(
        self,
        *,
        group_capacity: int = 1_024,
        member_capacity: int = 65_536,
        receipt_capacity: int = 65_536,
        byte_capacity: int = 64 * 1024 * 1024,
    ) -> None:
        self._group_capacity = _positive_int(group_capacity, "group_capacity")
        self._member_capacity = _positive_int(member_capacity, "member_capacity")
        self._receipt_capacity = _positive_int(receipt_capacity, "receipt_capacity")
        self._byte_capacity = _positive_int(byte_capacity, "byte_capacity")
        self._dispatcher_id = _random_hex(16, "persistent SMB dispatcher id")
        self._secret = secrets.token_bytes(32)
        if type(self._secret) is not bytes or len(self._secret) != 32:
            raise EventContractError("Persistent SMB authority secret generation failed")
        self._lock = Lock()
        self._next_group_id = 1
        self._groups: dict[int, _PersistentSmbGroupRecord] = {}
        self._group_token_locators: dict[int, int] = {}
        self._member_token_locators: dict[int, tuple[int, int]] = {}
        self._certification_locators: dict[int, tuple[int, int]] = {}
        self._commit_receipt_locators: dict[int, tuple[int, int]] = {}
        self._inactive_members = 0
        self._certified_members = 0
        self._committed_unacknowledged_members = 0
        self._retained_commit_receipts = 0
        self._retained_bytes = 0
        self._retained_group_bytes = 0
        self._reserved_member_capacity = 0
        self._reserved_receipt_capacity = 0
        self._reserved_byte_capacity = 0
        self._high_water_groups = 0
        self._high_water_members = 0
        self._high_water_certified_members = 0
        self._high_water_committed_unacknowledged_members = 0
        self._high_water_commit_receipts = 0
        self._high_water_bytes = 0
        self._table_backing_bytes = self._dict_backing_bytes(
            self._groups,
            self._group_token_locators,
            self._member_token_locators,
            self._certification_locators,
            self._commit_receipt_locators,
        )
        self._high_water_table_backing_bytes = self._table_backing_bytes

    def __copy__(self) -> PersistentSmbProjectionGroupAuthority:
        """Reject shallow authority aliases that would share private locators."""

        raise EventContractError("Persistent SMB projection authority is noncopyable")

    def __deepcopy__(
        self,
        _memo: dict[int, object],
    ) -> PersistentSmbProjectionGroupAuthority:
        """Reject deep authority aliases that cannot preserve exact ownership."""

        raise EventContractError("Persistent SMB projection authority is noncopyable")

    @property
    def dispatcher_id(self) -> str:
        """Return this authority's opaque process-local dispatcher identity."""

        return self._dispatcher_id

    @staticmethod
    def _dict_backing_bytes(*tables: dict[object, object]) -> int:
        """Return O(1)-per-table exact Python dictionary backing sizes."""

        return sum(sys.getsizeof(table) for table in tables)

    def _record_table_delta_locked(self, before: int, after: int) -> None:
        """Apply one O(1) backing-size delta after a bounded map mutation."""

        self._table_backing_bytes += after - before
        self._high_water_table_backing_bytes = max(
            self._high_water_table_backing_bytes,
            self._table_backing_bytes,
        )

    def _group_integrity(
        self,
        *,
        group_id: int,
        generation_id: str,
        projection_configuration_digest: str,
        member_budget: int,
        byte_budget: int,
    ) -> str:
        payload = _frame(
            b"persistent-smb-projection-group-v2",
            self._dispatcher_id.encode("ascii"),
            group_id.to_bytes(8, "big"),
            generation_id.encode("ascii"),
            projection_configuration_digest.encode("ascii"),
            member_budget.to_bytes(8, "big"),
            byte_budget.to_bytes(8, "big"),
        )
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def _member_integrity(
        self,
        *,
        group: _PersistentSmbGroupFacts,
        reservation: _PersistentSmbMemberReservation,
        timing_context_digest: str,
        timing: _PersistentSmbTimingFacts,
    ) -> str:
        payload = _frame(
            b"persistent-smb-projection-member-v2",
            group.dispatcher_id.encode("ascii"),
            group.group_id.to_bytes(8, "big"),
            group.generation_id.encode("ascii"),
            reservation.member_id.to_bytes(8, "big"),
            reservation.member_ordinal.to_bytes(8, "big"),
            reservation.phase.value.encode("ascii"),
            reservation.operation_id.encode("utf-8"),
            reservation.operation_binding_digest.encode("ascii"),
            group.projection_configuration_digest.encode("ascii"),
            reservation.capsule_digest.encode("ascii"),
            timing_context_digest.encode("ascii"),
            timing.binding_id.encode("ascii"),
            timing.preparation_id.to_bytes(8, "big"),
            timing.base_state_digest.encode("ascii"),
            timing.overlay_digest.encode("ascii"),
            timing.integrity.encode("ascii"),
            reservation.retained_bytes.to_bytes(8, "big"),
        )
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def _timing_receipt_digest(receipt: object) -> str:
        """Snapshot one exact timing receipt shell into callback-free scalar material."""

        if type(receipt) is not SourceTimingPreparationReceipt:
            raise EventContractError("Persistent SMB timing receipt requires its exact type")
        try:
            token = object.__getattribute__(receipt, "binding_token")
            overlay_value = object.__getattribute__(receipt, "overlay_digest")
            committed_value = object.__getattribute__(receipt, "committed_state_digest")
            receipt_integrity_value = object.__getattribute__(receipt, "_integrity")
            if type(token) is not SourceTimingPreparationToken:
                raise EventContractError("Persistent SMB timing receipt token is malformed")
            preparation_id = object.__getattribute__(token, "preparation_id")
            base_value = object.__getattribute__(token, "base_state_digest")
            token_integrity_value = object.__getattribute__(token, "_integrity")
            preparation = _positive_int(preparation_id, "timing receipt preparation id")
            base = _sha256_hex(base_value, "timing receipt base-state digest")
            token_integrity = _sha256_hex(
                token_integrity_value,
                "timing receipt token integrity",
            )
            overlay = _sha256_hex(overlay_value, "timing receipt overlay digest")
            committed = _sha256_hex(
                committed_value,
                "timing receipt committed-state digest",
            )
            receipt_integrity = _sha256_hex(
                receipt_integrity_value,
                "timing receipt integrity",
            )
        except (AttributeError, TypeError, ValueError) as error:
            if type(error) is EventContractError:
                raise
            raise EventContractError("Persistent SMB timing receipt is malformed") from error
        return hashlib.sha256(
            _frame(
                b"persistent-smb-timing-receipt-v1",
                preparation.to_bytes(8, "big"),
                base.encode("ascii"),
                token_integrity.encode("ascii"),
                overlay.encode("ascii"),
                committed.encode("ascii"),
                receipt_integrity.encode("ascii"),
            )
        ).hexdigest()

    @staticmethod
    def _activation_payload(
        *,
        namespace: bytes,
        member: _PersistentSmbMemberFacts,
        timing_receipt_digest: str,
        topology_generation_digest: str,
        target_formats: tuple[str, ...],
        lifecycle_binding_digest: str,
        lifecycle_binding_generation: int,
        network_binding_digest: str,
        network_binding_generation: int,
        traffic_binding_digest: str,
        traffic_binding_generation: int,
        state: str,
    ) -> bytes:
        values = [
            namespace,
            member.dispatcher_id.encode("ascii"),
            member.group_id.to_bytes(8, "big"),
            member.generation_id.encode("ascii"),
            member.member_id.to_bytes(8, "big"),
            member.member_ordinal.to_bytes(8, "big"),
            member.phase.value.encode("ascii"),
            member.operation_id.encode("utf-8"),
            member.operation_binding_digest.encode("ascii"),
            member.capsule_digest.encode("ascii"),
            member.timing_context_digest.encode("ascii"),
            timing_receipt_digest.encode("ascii"),
            topology_generation_digest.encode("ascii"),
            len(target_formats).to_bytes(8, "big"),
        ]
        values.extend(target.encode("ascii") for target in target_formats)
        values.extend(
            (
                lifecycle_binding_digest.encode("ascii"),
                lifecycle_binding_generation.to_bytes(8, "big"),
                network_binding_digest.encode("ascii"),
                network_binding_generation.to_bytes(8, "big"),
                traffic_binding_digest.encode("ascii"),
                traffic_binding_generation.to_bytes(8, "big"),
                state.encode("ascii"),
            )
        )
        return _frame(*values)

    def _certification_integrity(
        self,
        *,
        member: _PersistentSmbMemberFacts,
        timing_receipt_digest: str,
        topology_generation_digest: str,
        target_formats: tuple[str, ...],
        lifecycle_binding_digest: str,
        lifecycle_binding_generation: int,
        network_binding_digest: str,
        network_binding_generation: int,
        traffic_binding_digest: str,
        traffic_binding_generation: int,
    ) -> str:
        payload = self._activation_payload(
            namespace=b"persistent-smb-projection-certification-v1",
            member=member,
            timing_receipt_digest=timing_receipt_digest,
            topology_generation_digest=topology_generation_digest,
            target_formats=target_formats,
            lifecycle_binding_digest=lifecycle_binding_digest,
            lifecycle_binding_generation=lifecycle_binding_generation,
            network_binding_digest=network_binding_digest,
            network_binding_generation=network_binding_generation,
            traffic_binding_digest=traffic_binding_digest,
            traffic_binding_generation=traffic_binding_generation,
            state="certified",
        )
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def _commit_receipt_integrity(
        self,
        *,
        member: _PersistentSmbMemberFacts,
        certification: _PersistentSmbCertificationFacts,
    ) -> str:
        payload = self._activation_payload(
            namespace=b"persistent-smb-projection-member-commit-v1",
            member=member,
            timing_receipt_digest=certification.timing_receipt_digest,
            topology_generation_digest=certification.topology_generation_digest,
            target_formats=certification.target_formats,
            lifecycle_binding_digest=certification.lifecycle_binding_digest,
            lifecycle_binding_generation=certification.lifecycle_binding_generation,
            network_binding_digest=certification.network_binding_digest,
            network_binding_generation=certification.network_binding_generation,
            traffic_binding_digest=certification.traffic_binding_digest,
            traffic_binding_generation=certification.traffic_binding_generation,
            state="committed_unacknowledged",
        )
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def _group_retained_bytes(
        projection_configuration_digest: str,
        generation_id: str,
    ) -> int:
        return (
            _GROUP_RETAINED_BASE_BYTES
            + len(projection_configuration_digest.encode("ascii"))
            + len(generation_id.encode("ascii"))
        )

    @staticmethod
    def _member_retained_bytes(*, operation_id: str, capsule: bytes) -> int:
        return _MEMBER_RETAINED_BASE_BYTES + len(operation_id.encode("utf-8")) + len(capsule)

    @staticmethod
    def _group_facts_match(
        snapshot: _PersistentSmbGroupFacts,
        trusted: _PersistentSmbGroupFacts,
    ) -> bool:
        return bool(
            snapshot.dispatcher_id == trusted.dispatcher_id
            and snapshot.group_id == trusted.group_id
            and snapshot.generation_id == trusted.generation_id
            and snapshot.projection_configuration_digest == trusted.projection_configuration_digest
            and snapshot.member_budget == trusted.member_budget
            and snapshot.byte_budget == trusted.byte_budget
            and hmac.compare_digest(snapshot.integrity, trusted.integrity)
        )

    @staticmethod
    def _timing_facts_match(
        snapshot: _PersistentSmbTimingFacts,
        trusted: _PersistentSmbTimingFacts,
    ) -> bool:
        return bool(
            snapshot.binding_id == trusted.binding_id
            and snapshot.preparation_id == trusted.preparation_id
            and snapshot.base_state_digest == trusted.base_state_digest
            and snapshot.overlay_digest == trusted.overlay_digest
            and snapshot.context_digest == trusted.context_digest
            and hmac.compare_digest(snapshot.integrity, trusted.integrity)
        )

    @classmethod
    def _member_facts_match(
        cls,
        snapshot: _PersistentSmbMemberFacts,
        trusted: _PersistentSmbMemberFacts,
    ) -> bool:
        return bool(
            snapshot.dispatcher_id == trusted.dispatcher_id
            and snapshot.group_id == trusted.group_id
            and snapshot.generation_id == trusted.generation_id
            and snapshot.member_id == trusted.member_id
            and snapshot.member_ordinal == trusted.member_ordinal
            and snapshot.phase is trusted.phase
            and snapshot.operation_id == trusted.operation_id
            and snapshot.operation_binding_digest == trusted.operation_binding_digest
            and snapshot.projection_configuration_digest == trusted.projection_configuration_digest
            and snapshot.capsule_digest == trusted.capsule_digest
            and snapshot.timing_context_digest == trusted.timing_context_digest
            and cls._timing_facts_match(snapshot.timing, trusted.timing)
            and snapshot.retained_bytes == trusted.retained_bytes
            and hmac.compare_digest(snapshot.integrity, trusted.integrity)
        )

    def _snapshot_group_token(self, token: object) -> _PersistentSmbGroupFacts | None:
        """Read every public slot once and reject before callback-capable operations."""

        if type(token) is not PersistentSmbProjectionGroupToken:
            return None
        try:
            dispatcher_id = object.__getattribute__(token, "dispatcher_id")
            group_id = object.__getattribute__(token, "group_id")
            generation_value = object.__getattribute__(token, "generation_id")
            configuration_value = object.__getattribute__(
                token,
                "projection_configuration_digest",
            )
            member_budget = object.__getattribute__(token, "member_budget")
            byte_budget = object.__getattribute__(token, "byte_budget")
            integrity = object.__getattribute__(token, "_integrity")
            if (
                type(dispatcher_id) is not str
                or type(group_id) is not int
                or type(generation_value) is not str
                or type(configuration_value) is not str
                or type(member_budget) is not int
                or type(byte_budget) is not int
                or type(integrity) is not str
            ):
                return None
            if (
                dispatcher_id != self._dispatcher_id
                or group_id < 1
                or member_budget < 1
                or member_budget > _MAX_SIGNED_63
                or byte_budget < 1
                or byte_budget > _MAX_SIGNED_63
            ):
                return None
            generation = _sha256_hex(
                generation_value,
                "persistent SMB group generation id",
            )
            configuration = _sha256_hex(
                configuration_value,
                "projection configuration digest",
            )
            expected = self._group_integrity(
                group_id=group_id,
                generation_id=generation,
                projection_configuration_digest=configuration,
                member_budget=member_budget,
                byte_budget=byte_budget,
            )
            if not hmac.compare_digest(integrity, expected):
                return None
            return _PersistentSmbGroupFacts(
                dispatcher_id=dispatcher_id,
                group_id=group_id,
                generation_id=generation,
                projection_configuration_digest=configuration,
                member_budget=member_budget,
                byte_budget=byte_budget,
                integrity=integrity,
            )
        except BaseException:
            return None

    @staticmethod
    def _snapshot_timing_binding(
        binding: object,
    ) -> _PersistentSmbTimingFacts | None:
        """Snapshot an exact detached binding without invoking public callbacks."""

        if type(binding) is not SourceTimingDetachedPreparationBinding:
            return None
        try:
            binding_id_value = object.__getattribute__(binding, "binding_id")
            preparation_id = object.__getattribute__(binding, "preparation_id")
            base_value = object.__getattribute__(binding, "base_state_digest")
            overlay_value = object.__getattribute__(binding, "overlay_digest")
            context_value = object.__getattribute__(binding, "context_digest")
            integrity_value = object.__getattribute__(binding, "_integrity")
            if (
                type(binding_id_value) is not str
                or type(preparation_id) is not int
                or type(base_value) is not str
                or type(overlay_value) is not str
                or type(context_value) is not str
                or type(integrity_value) is not str
                or preparation_id < 1
                or preparation_id > _MAX_SIGNED_63
            ):
                return None
            return _PersistentSmbTimingFacts(
                binding_id=_sha256_hex(
                    binding_id_value,
                    "detached timing binding id",
                ),
                preparation_id=preparation_id,
                base_state_digest=_sha256_hex(
                    base_value,
                    "detached timing base-state digest",
                ),
                overlay_digest=_sha256_hex(
                    overlay_value,
                    "detached timing overlay digest",
                ),
                context_digest=_sha256_hex(
                    context_value,
                    "detached timing context digest",
                ),
                integrity=_sha256_hex(
                    integrity_value,
                    "detached timing binding integrity",
                ),
            )
        except BaseException:
            return None

    def _snapshot_member_token(
        self,
        token: object,
    ) -> tuple[_PersistentSmbMemberFacts, SourceTimingDetachedPreparationBinding] | None:
        """Snapshot one exact member carrier without callback-capable traversal."""

        if type(token) is not PersistentSmbProjectionMemberToken:
            return None
        try:
            dispatcher_id = object.__getattribute__(token, "dispatcher_id")
            group_id = object.__getattribute__(token, "group_id")
            generation_value = object.__getattribute__(token, "generation_id")
            member_id = object.__getattribute__(token, "member_id")
            member_ordinal = object.__getattribute__(token, "member_ordinal")
            phase = object.__getattribute__(token, "phase")
            operation_value = object.__getattribute__(token, "operation_id")
            owner_value = object.__getattribute__(token, "operation_binding_digest")
            configuration_value = object.__getattribute__(
                token,
                "projection_configuration_digest",
            )
            capsule_value = object.__getattribute__(token, "capsule_digest")
            context_value = object.__getattribute__(token, "timing_context_digest")
            binding = object.__getattribute__(token, "timing_binding")
            retained_bytes = object.__getattribute__(token, "retained_bytes")
            integrity = object.__getattribute__(token, "_integrity")
            if (
                type(dispatcher_id) is not str
                or type(group_id) is not int
                or type(generation_value) is not str
                or type(member_id) is not int
                or type(member_ordinal) is not int
                or type(phase) is not PersistentSmbProjectionPhase
                or type(operation_value) is not str
                or type(owner_value) is not str
                or type(configuration_value) is not str
                or type(capsule_value) is not str
                or type(context_value) is not str
                or type(binding) is not SourceTimingDetachedPreparationBinding
                or type(retained_bytes) is not int
                or type(integrity) is not str
            ):
                return None
            if (
                dispatcher_id != self._dispatcher_id
                or group_id < 1
                or member_id < 1
                or member_ordinal < 0
                or retained_bytes < _MEMBER_RETAINED_BASE_BYTES
                or retained_bytes > _MAX_SIGNED_63
            ):
                return None
            generation = _sha256_hex(
                generation_value,
                "persistent SMB group generation id",
            )
            operation = _bounded_text(
                operation_value,
                "persistent SMB operation id",
                _MAX_OPERATION_ID_UTF8_BYTES,
            )
            owner = _sha256_hex(
                owner_value,
                "persistent SMB operation binding digest",
            )
            configuration = _sha256_hex(
                configuration_value,
                "projection configuration digest",
            )
            capsule_digest = _sha256_hex(
                capsule_value,
                "projection capsule digest",
            )
            context = _sha256_hex(
                context_value,
                "detached timing context digest",
            )
            timing = self._snapshot_timing_binding(binding)
            if timing is None or timing.context_digest != context:
                return None
            group_facts = _PersistentSmbGroupFacts(
                dispatcher_id=dispatcher_id,
                group_id=group_id,
                generation_id=generation,
                projection_configuration_digest=configuration,
                member_budget=1,
                byte_budget=1,
                integrity="",
            )
            reservation = _PersistentSmbMemberReservation(
                group_id=group_id,
                member_id=member_id,
                member_ordinal=member_ordinal,
                phase=phase,
                operation_id=operation,
                operation_binding_digest=owner,
                capsule_digest=capsule_digest,
                retained_bytes=retained_bytes,
            )
            expected = self._member_integrity(
                group=group_facts,
                reservation=reservation,
                timing_context_digest=context,
                timing=timing,
            )
            if not hmac.compare_digest(integrity, expected):
                return None
            return (
                _PersistentSmbMemberFacts(
                    dispatcher_id=dispatcher_id,
                    group_id=group_id,
                    generation_id=generation,
                    member_id=member_id,
                    member_ordinal=member_ordinal,
                    phase=phase,
                    operation_id=operation,
                    operation_binding_digest=owner,
                    projection_configuration_digest=configuration,
                    capsule_digest=capsule_digest,
                    timing_context_digest=context,
                    timing=timing,
                    retained_bytes=retained_bytes,
                    integrity=integrity,
                ),
                binding,
            )
        except BaseException:
            return None

    def _snapshot_certification(
        self,
        carrier: object,
    ) -> _PersistentSmbCertificationFacts | None:
        """Snapshot one exact certification without invoking caller behavior."""

        if type(carrier) is not PersistentSmbProjectionMemberCertification:
            return None
        try:
            values = tuple(
                object.__getattribute__(carrier, name)
                for name in (
                    "dispatcher_id",
                    "group_id",
                    "generation_id",
                    "member_id",
                    "member_ordinal",
                    "phase",
                    "operation_id",
                    "operation_binding_digest",
                    "capsule_digest",
                    "timing_context_digest",
                    "timing_receipt_digest",
                    "topology_generation_digest",
                    "target_formats",
                    "lifecycle_binding_digest",
                    "lifecycle_binding_generation",
                    "network_binding_digest",
                    "network_binding_generation",
                    "traffic_binding_digest",
                    "traffic_binding_generation",
                    "expected_timing_receipt",
                    "_integrity",
                )
            )
            (
                dispatcher_id,
                group_id,
                generation_value,
                member_id,
                member_ordinal,
                phase,
                operation_value,
                operation_binding_value,
                capsule_value,
                timing_context_value,
                timing_receipt_value,
                topology_value,
                targets_value,
                lifecycle_value,
                lifecycle_generation,
                network_value,
                network_generation,
                traffic_value,
                traffic_generation,
                expected_receipt,
                integrity,
            ) = values
            if (
                type(dispatcher_id) is not str
                or dispatcher_id != self._dispatcher_id
                or type(group_id) is not int
                or group_id < 1
                or type(member_id) is not int
                or member_id < 1
                or type(member_ordinal) is not int
                or member_ordinal < 0
                or type(phase) is not PersistentSmbProjectionPhase
                or type(expected_receipt) is not SourceTimingPreparationReceipt
                or type(integrity) is not str
            ):
                return None
            generation = _sha256_hex(generation_value, "certification generation id")
            operation = _bounded_text(
                operation_value,
                "certification operation id",
                _MAX_OPERATION_ID_UTF8_BYTES,
            )
            operation_binding = _sha256_hex(
                operation_binding_value,
                "certification operation binding digest",
            )
            capsule = _sha256_hex(capsule_value, "certification capsule digest")
            timing_context = _sha256_hex(
                timing_context_value,
                "certification timing context digest",
            )
            timing_receipt = _sha256_hex(
                timing_receipt_value,
                "certification timing receipt digest",
            )
            if timing_receipt != self._timing_receipt_digest(expected_receipt):
                return None
            topology = _sha256_hex(
                topology_value,
                "certification topology generation digest",
            )
            targets = _target_formats(targets_value)
            lifecycle = _sha256_hex(
                lifecycle_value,
                "certification lifecycle binding digest",
            )
            lifecycle_gen = _positive_int(
                lifecycle_generation,
                "certification lifecycle binding generation",
            )
            network = _sha256_hex(network_value, "certification network binding digest")
            network_gen = _positive_int(
                network_generation,
                "certification network binding generation",
            )
            traffic = _sha256_hex(traffic_value, "certification traffic binding digest")
            traffic_gen = _positive_int(
                traffic_generation,
                "certification traffic binding generation",
            )
            integrity_digest = _sha256_hex(integrity, "certification integrity")
            return _PersistentSmbCertificationFacts(
                dispatcher_id=dispatcher_id,
                group_id=group_id,
                generation_id=generation,
                member_id=member_id,
                member_ordinal=member_ordinal,
                phase=phase,
                operation_id=operation,
                operation_binding_digest=operation_binding,
                capsule_digest=capsule,
                timing_context_digest=timing_context,
                timing_receipt_digest=timing_receipt,
                topology_generation_digest=topology,
                target_formats=targets,
                lifecycle_binding_digest=lifecycle,
                lifecycle_binding_generation=lifecycle_gen,
                network_binding_digest=network,
                network_binding_generation=network_gen,
                traffic_binding_digest=traffic,
                traffic_binding_generation=traffic_gen,
                expected_timing_receipt=expected_receipt,
                integrity=integrity_digest,
            )
        except BaseException:
            return None

    def _snapshot_commit_receipt(
        self,
        receipt: object,
    ) -> _PersistentSmbCommitReceiptFacts | None:
        """Snapshot one exact committed receipt without caller callbacks."""

        if type(receipt) is not PersistentSmbProjectionMemberCommitReceipt:
            return None
        try:
            values = tuple(
                object.__getattribute__(receipt, name)
                for name in (
                    "dispatcher_id",
                    "group_id",
                    "generation_id",
                    "member_id",
                    "member_ordinal",
                    "phase",
                    "operation_id",
                    "operation_binding_digest",
                    "capsule_digest",
                    "timing_context_digest",
                    "timing_receipt_digest",
                    "topology_generation_digest",
                    "target_formats",
                    "lifecycle_binding_digest",
                    "lifecycle_binding_generation",
                    "network_binding_digest",
                    "network_binding_generation",
                    "traffic_binding_digest",
                    "traffic_binding_generation",
                    "state",
                    "_integrity",
                )
            )
            (
                dispatcher_id,
                group_id,
                generation_value,
                member_id,
                member_ordinal,
                phase,
                operation_value,
                operation_binding_value,
                capsule_value,
                timing_context_value,
                timing_receipt_value,
                topology_value,
                targets_value,
                lifecycle_value,
                lifecycle_generation,
                network_value,
                network_generation,
                traffic_value,
                traffic_generation,
                state,
                integrity,
            ) = values
            if (
                type(dispatcher_id) is not str
                or dispatcher_id != self._dispatcher_id
                or type(group_id) is not int
                or group_id < 1
                or type(member_id) is not int
                or member_id < 1
                or type(member_ordinal) is not int
                or member_ordinal < 0
                or type(phase) is not PersistentSmbProjectionPhase
                or type(state) is not str
                or state != "committed_unacknowledged"
                or type(integrity) is not str
            ):
                return None
            return _PersistentSmbCommitReceiptFacts(
                dispatcher_id=dispatcher_id,
                group_id=group_id,
                generation_id=_sha256_hex(generation_value, "commit generation id"),
                member_id=member_id,
                member_ordinal=member_ordinal,
                phase=phase,
                operation_id=_bounded_text(
                    operation_value,
                    "commit operation id",
                    _MAX_OPERATION_ID_UTF8_BYTES,
                ),
                operation_binding_digest=_sha256_hex(
                    operation_binding_value,
                    "commit operation binding digest",
                ),
                capsule_digest=_sha256_hex(capsule_value, "commit capsule digest"),
                timing_context_digest=_sha256_hex(
                    timing_context_value,
                    "commit timing context digest",
                ),
                timing_receipt_digest=_sha256_hex(
                    timing_receipt_value,
                    "commit timing receipt digest",
                ),
                topology_generation_digest=_sha256_hex(
                    topology_value,
                    "commit topology generation digest",
                ),
                target_formats=_target_formats(targets_value),
                lifecycle_binding_digest=_sha256_hex(
                    lifecycle_value,
                    "commit lifecycle binding digest",
                ),
                lifecycle_binding_generation=_positive_int(
                    lifecycle_generation,
                    "commit lifecycle binding generation",
                ),
                network_binding_digest=_sha256_hex(
                    network_value,
                    "commit network binding digest",
                ),
                network_binding_generation=_positive_int(
                    network_generation,
                    "commit network binding generation",
                ),
                traffic_binding_digest=_sha256_hex(
                    traffic_value,
                    "commit traffic binding digest",
                ),
                traffic_binding_generation=_positive_int(
                    traffic_generation,
                    "commit traffic binding generation",
                ),
                state=state,
                integrity=_sha256_hex(integrity, "commit receipt integrity"),
            )
        except BaseException:
            return None

    def _certification_facts_match(
        self,
        snapshot: _PersistentSmbCertificationFacts,
        member: _PersistentSmbMemberFacts,
    ) -> bool:
        expected = self._certification_integrity(
            member=member,
            timing_receipt_digest=snapshot.timing_receipt_digest,
            topology_generation_digest=snapshot.topology_generation_digest,
            target_formats=snapshot.target_formats,
            lifecycle_binding_digest=snapshot.lifecycle_binding_digest,
            lifecycle_binding_generation=snapshot.lifecycle_binding_generation,
            network_binding_digest=snapshot.network_binding_digest,
            network_binding_generation=snapshot.network_binding_generation,
            traffic_binding_digest=snapshot.traffic_binding_digest,
            traffic_binding_generation=snapshot.traffic_binding_generation,
        )
        return bool(
            snapshot.dispatcher_id == member.dispatcher_id
            and snapshot.group_id == member.group_id
            and snapshot.generation_id == member.generation_id
            and snapshot.member_id == member.member_id
            and snapshot.member_ordinal == member.member_ordinal
            and snapshot.phase is member.phase
            and snapshot.operation_id == member.operation_id
            and snapshot.operation_binding_digest == member.operation_binding_digest
            and snapshot.capsule_digest == member.capsule_digest
            and snapshot.timing_context_digest == member.timing_context_digest
            and hmac.compare_digest(snapshot.integrity, expected)
        )

    def _commit_receipt_facts_match(
        self,
        snapshot: _PersistentSmbCommitReceiptFacts,
        member: _PersistentSmbMemberFacts,
        certification: _PersistentSmbCertificationFacts,
    ) -> bool:
        expected = self._commit_receipt_integrity(
            member=member,
            certification=certification,
        )
        return bool(
            snapshot.dispatcher_id == member.dispatcher_id
            and snapshot.group_id == member.group_id
            and snapshot.generation_id == member.generation_id
            and snapshot.member_id == member.member_id
            and snapshot.member_ordinal == member.member_ordinal
            and snapshot.phase is member.phase
            and snapshot.operation_id == member.operation_id
            and snapshot.operation_binding_digest == member.operation_binding_digest
            and snapshot.capsule_digest == member.capsule_digest
            and snapshot.timing_context_digest == member.timing_context_digest
            and snapshot.timing_receipt_digest == certification.timing_receipt_digest
            and snapshot.topology_generation_digest == certification.topology_generation_digest
            and snapshot.target_formats == certification.target_formats
            and snapshot.lifecycle_binding_digest == certification.lifecycle_binding_digest
            and snapshot.lifecycle_binding_generation == certification.lifecycle_binding_generation
            and snapshot.network_binding_digest == certification.network_binding_digest
            and snapshot.network_binding_generation == certification.network_binding_generation
            and snapshot.traffic_binding_digest == certification.traffic_binding_digest
            and snapshot.traffic_binding_generation == certification.traffic_binding_generation
            and snapshot.state == "committed_unacknowledged"
            and hmac.compare_digest(snapshot.integrity, expected)
        )

    def _group_for_token_locked(
        self,
        token: PersistentSmbProjectionGroupToken,
    ) -> _PersistentSmbGroupRecord | None:
        group_id = self._group_token_locators.get(id(token))
        record = self._groups.get(group_id) if group_id is not None else None
        if (
            record is None
            or record.owner_ref() is not self
            or record.token is not token
            or record.state != "open"
        ):
            return None
        return record

    def _member_for_token_locked(
        self,
        token: PersistentSmbProjectionMemberToken,
    ) -> tuple[_PersistentSmbGroupRecord, _PersistentSmbMemberRecord] | None:
        locator = self._member_token_locators.get(id(token))
        if locator is None:
            return None
        group = self._groups.get(locator[0])
        member = group.members.get(locator[1]) if group is not None else None
        if (
            group is None
            or group.owner_ref() is not self
            or member is None
            or member.token is not token
        ):
            return None
        return group, member

    def _member_for_certification_locked(
        self,
        carrier: PersistentSmbProjectionMemberCertification,
    ) -> tuple[_PersistentSmbGroupRecord, _PersistentSmbMemberRecord] | None:
        locator = self._certification_locators.get(id(carrier))
        if locator is None:
            return None
        group = self._groups.get(locator[0])
        member = group.members.get(locator[1]) if group is not None else None
        if (
            group is None
            or group.owner_ref() is not self
            or member is None
            or member.certification is not carrier
        ):
            return None
        return group, member

    def _member_for_commit_receipt_locked(
        self,
        receipt: PersistentSmbProjectionMemberCommitReceipt,
    ) -> tuple[_PersistentSmbGroupRecord, _PersistentSmbMemberRecord] | None:
        locator = self._commit_receipt_locators.get(id(receipt))
        if locator is None:
            return None
        group = self._groups.get(locator[0])
        member = group.members.get(locator[1]) if group is not None else None
        if (
            group is None
            or group.owner_ref() is not self
            or member is None
            or member.commit_receipt is not receipt
        ):
            return None
        return group, member

    def _preflight_group_capacity_locked(
        self,
        *,
        member_budget: int,
        byte_budget: int,
        group_bytes: int,
    ) -> None:
        if len(self._groups) >= self._group_capacity:
            raise EventContractError("Persistent SMB projection group capacity is exhausted")
        if self._reserved_member_capacity + member_budget > self._member_capacity:
            raise EventContractError("Persistent SMB projection member capacity is exhausted")
        if self._reserved_receipt_capacity + member_budget > self._receipt_capacity:
            raise EventContractError("Persistent SMB projection receipt capacity is exhausted")
        if (
            self._retained_group_bytes + group_bytes + self._reserved_byte_capacity + byte_budget
            > self._byte_capacity
        ):
            raise EventContractError("Persistent SMB projection byte capacity is exhausted")

    def _remove_member_locked(
        self,
        group: _PersistentSmbGroupRecord,
        member: _PersistentSmbMemberRecord,
    ) -> None:
        """Remove one trusted member and every locator and live charge."""

        member_id = member.reservation.member_id
        operation = member.reservation.operation_id
        token = member.token
        maps_before = self._dict_backing_bytes(
            group.members,
            group.member_by_operation,
            self._member_token_locators,
            self._certification_locators,
            self._commit_receipt_locators,
        )
        if token is not None:
            locator = self._member_token_locators.get(id(token))
            if locator == (group.facts.group_id, member_id):
                self._member_token_locators.pop(id(token), None)
        certification = member.certification
        if certification is not None:
            locator = self._certification_locators.get(id(certification))
            if locator == (group.facts.group_id, member_id):
                self._certification_locators.pop(id(certification), None)
        commit_receipt = member.commit_receipt
        if commit_receipt is not None:
            locator = self._commit_receipt_locators.get(id(commit_receipt))
            if locator == (group.facts.group_id, member_id):
                self._commit_receipt_locators.pop(id(commit_receipt), None)
        group.members.pop(member_id, None)
        if group.member_by_operation.get(operation) == member_id:
            group.member_by_operation.pop(operation, None)
        if not group.members:
            group.members.clear()
        if not group.member_by_operation:
            group.member_by_operation.clear()
        if not self._member_token_locators:
            self._member_token_locators.clear()
        if not self._certification_locators:
            self._certification_locators.clear()
        if not self._commit_receipt_locators:
            self._commit_receipt_locators.clear()
        maps_after = self._dict_backing_bytes(
            group.members,
            group.member_by_operation,
            self._member_token_locators,
            self._certification_locators,
            self._commit_receipt_locators,
        )
        self._record_table_delta_locked(maps_before, maps_after)
        group.member_bytes -= member.retained_bytes
        group.retained_bytes -= member.retained_bytes
        self._retained_bytes -= member.retained_bytes
        if member.state in {"preparing", "inactive", "cancelling_inactive", "cancelling"}:
            self._inactive_members -= 1
        elif member.state in {"certified", "cancelling_certified"}:
            self._certified_members -= 1
        elif member.state in {"committed_unacknowledged", "acknowledging"}:
            self._committed_unacknowledged_members -= 1
        else:
            raise EventContractError("Persistent SMB member has an invalid retained state")
        if commit_receipt is not None:
            self._retained_commit_receipts -= 1
        member.token = None
        member.capsule = None
        member.facts = None
        member.timing_binding = None
        member.timing_owner_ref = None
        member.certification = None
        member.expected_timing_receipt = None
        member.commit_receipt = None
        member.state = "cancelled"

    @staticmethod
    def _member_context_digest(
        *,
        group: _PersistentSmbGroupFacts,
        reservation: _PersistentSmbMemberReservation,
    ) -> str:
        payload = _frame(
            b"persistent-smb-projection-member-context-v2",
            group.dispatcher_id.encode("ascii"),
            group.group_id.to_bytes(8, "big"),
            group.generation_id.encode("ascii"),
            group.integrity.encode("ascii"),
            reservation.member_id.to_bytes(8, "big"),
            reservation.member_ordinal.to_bytes(8, "big"),
            reservation.phase.value.encode("ascii"),
            reservation.operation_id.encode("utf-8"),
            reservation.operation_binding_digest.encode("ascii"),
            group.projection_configuration_digest.encode("ascii"),
            reservation.capsule_digest.encode("ascii"),
        )
        return hashlib.sha256(payload).hexdigest()

    def _preflight_group_reservation(
        self,
        *,
        member_budget: int,
        byte_budget: int,
    ) -> tuple[int, int]:
        """Validate and capacity-check one declaration without issuing identity."""

        members = _positive_int(member_budget, "member_budget")
        bytes_budget = _positive_int(byte_budget, "byte_budget")
        if members > self._member_capacity:
            raise EventContractError(
                "Persistent SMB group member budget exceeds authority capacity"
            )
        if members > self._receipt_capacity:
            raise EventContractError(
                "Persistent SMB group receipt budget exceeds authority capacity"
            )
        if bytes_budget > self._byte_capacity:
            raise EventContractError("Persistent SMB group byte budget exceeds authority capacity")
        provisional_group_bytes = self._group_retained_bytes("0" * 64, "0" * 64)
        with self._lock:
            self._preflight_group_capacity_locked(
                member_budget=members,
                byte_budget=bytes_budget,
                group_bytes=provisional_group_bytes,
            )
        return members, bytes_budget

    def reserve_group(
        self,
        *,
        projection_configuration_digest: str,
        member_budget: int,
        byte_budget: int,
    ) -> PersistentSmbProjectionGroupToken:
        """Reserve a group's complete declared capacity before canonical open."""

        configuration = _sha256_hex(
            projection_configuration_digest,
            "projection configuration digest",
        )
        members, bytes_budget = self._preflight_group_reservation(
            member_budget=member_budget,
            byte_budget=byte_budget,
        )

        # Reject deterministically exhausted admission before any RNG/allocation
        # used for the public generation token. A second locked check closes the
        # concurrent admission race.
        generation_id = _random_hex(32, "persistent SMB group generation id")
        group_bytes = self._group_retained_bytes(configuration, generation_id)

        with self._lock:
            self._preflight_group_capacity_locked(
                member_budget=members,
                byte_budget=bytes_budget,
                group_bytes=group_bytes,
            )
            group_id = self._next_group_id
            if group_id > _MAX_SIGNED_63:
                raise EventContractError("Persistent SMB group identity capacity is exhausted")
            integrity = self._group_integrity(
                group_id=group_id,
                generation_id=generation_id,
                projection_configuration_digest=configuration,
                member_budget=members,
                byte_budget=bytes_budget,
            )
            token = PersistentSmbProjectionGroupToken(
                dispatcher_id=self._dispatcher_id,
                group_id=group_id,
                generation_id=generation_id,
                projection_configuration_digest=configuration,
                member_budget=members,
                byte_budget=bytes_budget,
                _integrity=integrity,
            )
            facts = _PersistentSmbGroupFacts(
                dispatcher_id=self._dispatcher_id,
                group_id=group_id,
                generation_id=generation_id,
                projection_configuration_digest=configuration,
                member_budget=members,
                byte_budget=bytes_budget,
                integrity=integrity,
            )
            record = _PersistentSmbGroupRecord(
                owner_ref=ref(self),
                token=token,
                facts=facts,
                base_retained_bytes=group_bytes,
                retained_bytes=group_bytes,
            )
            maps_before = self._dict_backing_bytes(
                self._groups,
                self._group_token_locators,
            )
            try:
                self._groups[group_id] = record
                self._group_token_locators[id(token)] = group_id
            except BaseException:
                self._groups.pop(group_id, None)
                self._group_token_locators.pop(id(token), None)
                if not self._groups:
                    self._groups.clear()
                if not self._group_token_locators:
                    self._group_token_locators.clear()
                failed_maps_after = self._dict_backing_bytes(
                    self._groups,
                    self._group_token_locators,
                )
                self._record_table_delta_locked(maps_before, failed_maps_after)
                raise
            maps_after = self._dict_backing_bytes(
                self._groups,
                self._group_token_locators,
            )
            self._record_table_delta_locked(
                maps_before,
                maps_after + self._dict_backing_bytes(record.members, record.member_by_operation),
            )
            self._next_group_id += 1
            self._retained_group_bytes += group_bytes
            self._retained_bytes += group_bytes
            self._reserved_member_capacity += members
            self._reserved_receipt_capacity += members
            self._reserved_byte_capacity += bytes_budget
            self._high_water_groups = max(self._high_water_groups, len(self._groups))
            self._high_water_bytes = max(self._high_water_bytes, self._retained_bytes)
            return token

    def authenticates_group(self, token: object) -> bool:
        """Return whether one exact live group carrier is intact."""

        snapshot = self._snapshot_group_token(token)
        if snapshot is None:
            return False
        assert type(token) is PersistentSmbProjectionGroupToken
        with self._lock:
            record = self._group_for_token_locked(token)
            return bool(record is not None and self._group_facts_match(snapshot, record.facts))

    def prepare_member(
        self,
        group: PersistentSmbProjectionGroupToken,
        *,
        phase: PersistentSmbProjectionPhase,
        operation_id: str,
        operation_binding_digest: str,
        projection_capsule: bytes,
        timing_planner: SourceTimingPlanner,
        timing_preparation: SourceTimingPreparation,
    ) -> PersistentSmbProjectionMemberToken:
        """Freeze, charge, and install one inactive member before mutation.

        The opaque operation binding is framed into the member but is not
        authenticated here. Production activation is unavailable until a typed
        coordinator owns and authenticates that terminal result.
        """

        group_snapshot = self._snapshot_group_token(group)
        if group_snapshot is None:
            raise EventContractError("Persistent SMB projection group is foreign, copied, or stale")
        if type(phase) is not PersistentSmbProjectionPhase:
            raise EventContractError("Persistent SMB projection phase requires its exact enum")
        operation = _bounded_text(
            operation_id,
            "persistent SMB operation id",
            _MAX_OPERATION_ID_UTF8_BYTES,
        )
        owner_digest = _sha256_hex(
            operation_binding_digest,
            "persistent SMB operation binding digest",
        )
        if type(projection_capsule) is not bytes:
            raise EventContractError("Persistent SMB projection capsule requires exact bytes")
        if not projection_capsule or len(projection_capsule) > _MAX_PROJECTION_CAPSULE_BYTES:
            raise EventContractError(
                "Persistent SMB projection capsule must fit its non-empty byte bound"
            )
        if type(timing_planner) is not SourceTimingPlanner:
            raise EventContractError("Persistent SMB timing planner requires its exact owner type")
        if type(timing_preparation) is not SourceTimingPreparation:
            raise EventContractError("Persistent SMB timing preparation requires its exact type")
        timing_owner_ref = ref(timing_planner)
        capsule = memoryview(projection_capsule).tobytes()
        capsule_digest = hashlib.sha256(capsule).hexdigest()
        retained_bytes = self._member_retained_bytes(
            operation_id=operation,
            capsule=capsule,
        )

        existing = False
        with self._lock:
            group_record = self._group_for_token_locked(group)
            if group_record is None or not self._group_facts_match(
                group_snapshot, group_record.facts
            ):
                raise EventContractError("Persistent SMB projection group became stale")
            group_facts = group_record.facts
            existing_id = group_record.member_by_operation.get(operation)
            if existing_id is not None:
                retained = group_record.members.get(existing_id)
                reservation = retained.reservation if retained is not None else None
                if (
                    retained is None
                    or reservation is None
                    or retained.state != "inactive"
                    or retained.facts is None
                    or retained.token is None
                    or retained.timing_binding is None
                    or retained.timing_owner_ref is None
                    or retained.timing_owner_ref() is not timing_planner
                    or reservation.phase is not phase
                    or reservation.operation_binding_digest != owner_digest
                    or reservation.capsule_digest != capsule_digest
                ):
                    raise EventContractError(
                        "Persistent SMB operation id names different detached projection facts"
                    )
                existing = True
            else:
                if len(group_record.members) >= group_facts.member_budget:
                    raise EventContractError(
                        "Persistent SMB projection group member budget is exhausted"
                    )
                if group_record.member_bytes + retained_bytes > group_facts.byte_budget:
                    raise EventContractError(
                        "Persistent SMB projection group byte budget is exhausted"
                    )
                member_id = group_record.next_member_id
                member_ordinal = group_record.next_member_ordinal
                if member_id > _MAX_SIGNED_63 or member_ordinal > _MAX_SIGNED_63:
                    raise EventContractError(
                        "Persistent SMB projection member identity capacity is exhausted"
                    )
                reservation = _PersistentSmbMemberReservation(
                    group_id=group_facts.group_id,
                    member_id=member_id,
                    member_ordinal=member_ordinal,
                    phase=phase,
                    operation_id=operation,
                    operation_binding_digest=owner_digest,
                    capsule_digest=capsule_digest,
                    retained_bytes=retained_bytes,
                )
                placeholder = _PersistentSmbMemberRecord(
                    token=None,
                    capsule=None,
                    operation_id=operation,
                    operation_binding_digest=owner_digest,
                    capsule_digest=capsule_digest,
                    retained_bytes=retained_bytes,
                    reservation=reservation,
                    timing_owner_ref=timing_owner_ref,
                )
                maps_before = self._dict_backing_bytes(
                    group_record.members,
                    group_record.member_by_operation,
                )
                try:
                    group_record.members[member_id] = placeholder
                    group_record.member_by_operation[operation] = member_id
                except BaseException:
                    group_record.members.pop(member_id, None)
                    if group_record.member_by_operation.get(operation) == member_id:
                        group_record.member_by_operation.pop(operation, None)
                    if not group_record.members:
                        group_record.members.clear()
                    if not group_record.member_by_operation:
                        group_record.member_by_operation.clear()
                    failed_maps_after = self._dict_backing_bytes(
                        group_record.members,
                        group_record.member_by_operation,
                    )
                    self._record_table_delta_locked(maps_before, failed_maps_after)
                    raise
                maps_after = self._dict_backing_bytes(
                    group_record.members,
                    group_record.member_by_operation,
                )
                self._record_table_delta_locked(maps_before, maps_after)
                group_record.next_member_id += 1
                group_record.next_member_ordinal += 1
                group_record.member_bytes += retained_bytes
                group_record.retained_bytes += retained_bytes
                self._retained_bytes += retained_bytes
                self._inactive_members += 1
                self._high_water_members = max(
                    self._high_water_members,
                    self._inactive_members,
                )
                self._high_water_bytes = max(
                    self._high_water_bytes,
                    self._retained_bytes,
                )

        if existing:
            recovery = self.recover_inactive_member(
                group,
                operation_id=operation,
                operation_binding_digest=owner_digest,
                timing_planner=timing_planner,
            )
            return recovery.member_token

        timing_binding: SourceTimingDetachedPreparationBinding | None = None
        token: PersistentSmbProjectionMemberToken | None = None
        try:
            context_digest = self._member_context_digest(
                group=group_facts,
                reservation=reservation,
            )
            timing_binding = timing_planner.detach_preparation_binding(
                timing_preparation,
                context_digest=context_digest,
            )
            timing_facts = self._snapshot_timing_binding(timing_binding)
            if (
                timing_facts is None
                or timing_facts.context_digest != context_digest
                or not timing_planner.authenticates_detached_preparation_binding(
                    timing_binding,
                    context_digest=context_digest,
                )
            ):
                raise EventContractError("Detached source-timing binding is malformed or stale")
            integrity = self._member_integrity(
                group=group_facts,
                reservation=reservation,
                timing_context_digest=context_digest,
                timing=timing_facts,
            )
            member_facts = _PersistentSmbMemberFacts(
                dispatcher_id=group_facts.dispatcher_id,
                group_id=group_facts.group_id,
                generation_id=group_facts.generation_id,
                member_id=reservation.member_id,
                member_ordinal=reservation.member_ordinal,
                phase=reservation.phase,
                operation_id=reservation.operation_id,
                operation_binding_digest=reservation.operation_binding_digest,
                projection_configuration_digest=group_facts.projection_configuration_digest,
                capsule_digest=reservation.capsule_digest,
                timing_context_digest=context_digest,
                timing=timing_facts,
                retained_bytes=reservation.retained_bytes,
                integrity=integrity,
            )
            token = PersistentSmbProjectionMemberToken(
                dispatcher_id=member_facts.dispatcher_id,
                group_id=member_facts.group_id,
                generation_id=member_facts.generation_id,
                member_id=member_facts.member_id,
                member_ordinal=member_facts.member_ordinal,
                phase=member_facts.phase,
                operation_id=member_facts.operation_id,
                operation_binding_digest=member_facts.operation_binding_digest,
                projection_configuration_digest=member_facts.projection_configuration_digest,
                capsule_digest=member_facts.capsule_digest,
                timing_context_digest=member_facts.timing_context_digest,
                timing_binding=timing_binding,
                retained_bytes=member_facts.retained_bytes,
                _integrity=member_facts.integrity,
            )
            with self._lock:
                current_group = self._groups.get(group_facts.group_id)
                current = (
                    current_group.members.get(reservation.member_id)
                    if current_group is not None
                    else None
                )
                if (
                    current_group is not group_record
                    or current is not placeholder
                    or current.state != "preparing"
                    or id(token) in self._member_token_locators
                ):
                    raise EventContractError(
                        "Persistent SMB member reservation changed before preparation completed"
                    )
                maps_before = self._dict_backing_bytes(self._member_token_locators)
                try:
                    self._member_token_locators[id(token)] = (
                        group_facts.group_id,
                        reservation.member_id,
                    )
                except BaseException:
                    self._member_token_locators.pop(id(token), None)
                    if not self._member_token_locators:
                        self._member_token_locators.clear()
                    failed_maps_after = self._dict_backing_bytes(
                        self._member_token_locators,
                    )
                    self._record_table_delta_locked(maps_before, failed_maps_after)
                    raise
                maps_after = self._dict_backing_bytes(self._member_token_locators)
                self._record_table_delta_locked(maps_before, maps_after)
                current.token = token
                current.capsule = capsule
                current.facts = member_facts
                current.timing_binding = timing_binding
                current.state = "inactive"
            return token
        except BaseException:
            cleanup_error: BaseException | None = None
            if timing_binding is not None:
                try:
                    timing_planner.discard_detached_preparation_binding(timing_binding)
                except BaseException as error:
                    cleanup_error = error
            with self._lock:
                current_group = self._groups.get(group_facts.group_id)
                current = (
                    current_group.members.get(reservation.member_id)
                    if current_group is not None
                    else None
                )
                if current_group is group_record and current is placeholder:
                    self._remove_member_locked(current_group, current)
            if cleanup_error is not None:
                raise EventContractError(
                    "Persistent SMB member failure could not reclaim its detached timing binding"
                ) from cleanup_error
            raise

    def authenticates_member_token(
        self,
        token: object,
        *,
        timing_planner: SourceTimingPlanner,
    ) -> bool:
        """Return whether one exact inactive carrier and timing proof are live."""

        if type(timing_planner) is not SourceTimingPlanner:
            return False
        snapshot_result = self._snapshot_member_token(token)
        if snapshot_result is None:
            return False
        snapshot, binding = snapshot_result
        assert type(token) is PersistentSmbProjectionMemberToken
        with self._lock:
            located = self._member_for_token_locked(token)
            if located is None:
                return False
            group, member = located
            trusted = member.facts
            if (
                trusted is None
                or member.state != "inactive"
                or member.timing_binding is not binding
                or member.timing_owner_ref is None
                or member.timing_owner_ref() is not timing_planner
                or group.facts.group_id != trusted.group_id
                or not self._member_facts_match(snapshot, trusted)
            ):
                return False
            context_digest = trusted.timing_context_digest
        if not timing_planner.authenticates_detached_preparation_binding(
            binding,
            context_digest=context_digest,
        ):
            return False
        final_snapshot = self._snapshot_member_token(token)
        if final_snapshot is None or final_snapshot[1] is not binding:
            return False
        with self._lock:
            located = self._member_for_token_locked(token)
            trusted = located[1].facts if located is not None else None
            return bool(
                located is not None
                and located[1].state == "inactive"
                and located[1].timing_binding is binding
                and located[1].timing_owner_ref is not None
                and located[1].timing_owner_ref() is timing_planner
                and trusted is not None
                and self._member_facts_match(final_snapshot[0], trusted)
            )

    def certify_member(
        self,
        token: PersistentSmbProjectionMemberToken,
        *,
        target_formats: tuple[str, ...],
        lifecycle_binding_digest: str,
        lifecycle_binding_generation: int,
        network_binding_digest: str,
        network_binding_generation: int,
        traffic_binding_digest: str,
        traffic_binding_generation: int,
        topology_generation_digest: str,
        timing_planner: SourceTimingPlanner,
        expected_timing_receipt: SourceTimingPreparationReceipt,
    ) -> PersistentSmbProjectionMemberCertification:
        """Claim one inactive member for exact owner bindings and target intent."""

        if type(timing_planner) is not SourceTimingPlanner:
            raise EventContractError("Persistent SMB timing planner requires its exact owner type")
        targets = _target_formats(target_formats)
        lifecycle_digest = _sha256_hex(
            lifecycle_binding_digest,
            "persistent SMB lifecycle binding digest",
        )
        lifecycle_generation = _positive_int(
            lifecycle_binding_generation,
            "persistent SMB lifecycle binding generation",
        )
        network_digest = _sha256_hex(
            network_binding_digest,
            "persistent SMB network binding digest",
        )
        network_generation = _positive_int(
            network_binding_generation,
            "persistent SMB network binding generation",
        )
        traffic_digest = _sha256_hex(
            traffic_binding_digest,
            "persistent SMB traffic binding digest",
        )
        traffic_generation = _positive_int(
            traffic_binding_generation,
            "persistent SMB traffic binding generation",
        )
        topology_digest = _sha256_hex(
            topology_generation_digest,
            "persistent SMB topology generation digest",
        )
        timing_receipt_digest = self._timing_receipt_digest(expected_timing_receipt)
        token_snapshot = self._snapshot_member_token(token)
        if token_snapshot is None:
            raise EventContractError("Persistent SMB member is foreign, copied, or stale")
        snapshot_facts, snapshot_binding = token_snapshot

        def request_matches(existing: _PersistentSmbCertificationFacts) -> bool:
            return bool(
                existing.target_formats == targets
                and existing.lifecycle_binding_digest == lifecycle_digest
                and existing.lifecycle_binding_generation == lifecycle_generation
                and existing.network_binding_digest == network_digest
                and existing.network_binding_generation == network_generation
                and existing.traffic_binding_digest == traffic_digest
                and existing.traffic_binding_generation == traffic_generation
                and existing.topology_generation_digest == topology_digest
                and existing.timing_receipt_digest == timing_receipt_digest
                and existing.expected_timing_receipt is expected_timing_receipt
            )

        with self._lock:
            located = self._member_for_token_locked(token)
            if located is None:
                raise EventContractError("Persistent SMB member is foreign, copied, or stale")
            group, member = located
            facts = member.facts
            if facts is None or not self._member_facts_match(snapshot_facts, facts):
                raise EventContractError("Persistent SMB member is foreign, copied, or stale")
            if member.state in {"certified", "committed_unacknowledged"}:
                existing = member.certification
                existing_snapshot = self._snapshot_certification(existing)
                if (
                    existing is not None
                    and existing_snapshot is not None
                    and self._certification_facts_match(existing_snapshot, facts)
                    and request_matches(existing_snapshot)
                ):
                    return existing
                raise EventContractError(
                    "Persistent SMB member already has different certified facts"
                )
            if member.state != "inactive":
                raise EventContractError("Persistent SMB member is not inactive")
            binding = member.timing_binding
            timing_owner_ref = member.timing_owner_ref
            if (
                binding is None
                or binding is not snapshot_binding
                or timing_owner_ref is None
                or timing_owner_ref() is not timing_planner
            ):
                raise EventContractError("Persistent SMB member has a stale timing binding")
            group_id = group.facts.group_id
            member_id = facts.member_id
            context_digest = facts.timing_context_digest

        if not timing_planner.authenticates_expected_detached_preparation_binding(
            binding,
            expected_timing_receipt,
            context_digest=context_digest,
        ):
            raise EventContractError(
                "Persistent SMB member expected source timing is foreign, committed, or stale"
            )

        integrity = self._certification_integrity(
            member=facts,
            timing_receipt_digest=timing_receipt_digest,
            topology_generation_digest=topology_digest,
            target_formats=targets,
            lifecycle_binding_digest=lifecycle_digest,
            lifecycle_binding_generation=lifecycle_generation,
            network_binding_digest=network_digest,
            network_binding_generation=network_generation,
            traffic_binding_digest=traffic_digest,
            traffic_binding_generation=traffic_generation,
        )
        certification = PersistentSmbProjectionMemberCertification(
            dispatcher_id=facts.dispatcher_id,
            group_id=facts.group_id,
            generation_id=facts.generation_id,
            member_id=facts.member_id,
            member_ordinal=facts.member_ordinal,
            phase=facts.phase,
            operation_id=facts.operation_id,
            operation_binding_digest=facts.operation_binding_digest,
            capsule_digest=facts.capsule_digest,
            timing_context_digest=facts.timing_context_digest,
            timing_receipt_digest=timing_receipt_digest,
            topology_generation_digest=topology_digest,
            target_formats=targets,
            lifecycle_binding_digest=lifecycle_digest,
            lifecycle_binding_generation=lifecycle_generation,
            network_binding_digest=network_digest,
            network_binding_generation=network_generation,
            traffic_binding_digest=traffic_digest,
            traffic_binding_generation=traffic_generation,
            expected_timing_receipt=expected_timing_receipt,
            _integrity=integrity,
        )
        with self._lock:
            retained_group = self._groups.get(group_id)
            retained = retained_group.members.get(member_id) if retained_group is not None else None
            if (
                retained_group is not group
                or retained is not member
                or retained.state != "inactive"
                or retained.facts is not facts
                or retained.timing_binding is not binding
                or retained.timing_owner_ref is not timing_owner_ref
                or timing_owner_ref() is not timing_planner
            ):
                if retained is member and retained.state in {
                    "certified",
                    "committed_unacknowledged",
                }:
                    existing = retained.certification
                    existing_snapshot = self._snapshot_certification(existing)
                    if (
                        existing is not None
                        and existing_snapshot is not None
                        and self._certification_facts_match(existing_snapshot, facts)
                        and request_matches(existing_snapshot)
                    ):
                        return existing
                raise EventContractError("Persistent SMB member changed during certification")
            maps_before = self._dict_backing_bytes(self._certification_locators)
            try:
                self._certification_locators[id(certification)] = (group_id, member_id)
            except BaseException:
                self._certification_locators.pop(id(certification), None)
                self._record_table_delta_locked(
                    maps_before,
                    self._dict_backing_bytes(self._certification_locators),
                )
                raise
            self._record_table_delta_locked(
                maps_before,
                self._dict_backing_bytes(self._certification_locators),
            )
            member.certification = certification
            member.expected_timing_receipt = expected_timing_receipt
            member.state = "certified"
            self._inactive_members -= 1
            self._certified_members += 1
            self._high_water_certified_members = max(
                self._high_water_certified_members,
                self._certified_members,
            )
            return certification

    def commit_member(
        self,
        certification: PersistentSmbProjectionMemberCertification,
        *,
        timing_planner: SourceTimingPlanner,
    ) -> PersistentSmbProjectionMemberCommitReceipt:
        """Commit one certified member after its exact source timing commits."""

        if type(timing_planner) is not SourceTimingPlanner:
            raise EventContractError("Persistent SMB timing planner requires its exact owner type")
        certification_snapshot = self._snapshot_certification(certification)
        if certification_snapshot is None:
            raise EventContractError(
                "Persistent SMB certification is copied, foreign, tampered, or stale"
            )
        with self._lock:
            located = self._member_for_certification_locked(certification)
            if located is None:
                raise EventContractError(
                    "Persistent SMB certification is copied, foreign, tampered, or stale"
                )
            group, member = located
            facts = member.facts
            if (
                facts is None
                or member.state not in {"certified", "committed_unacknowledged"}
                or member.expected_timing_receipt
                is not certification_snapshot.expected_timing_receipt
                or not self._certification_facts_match(certification_snapshot, facts)
            ):
                raise EventContractError(
                    "Persistent SMB certification is copied, foreign, tampered, or stale"
                )
            binding = member.timing_binding
            timing_owner_ref = member.timing_owner_ref
            if (
                binding is None
                or timing_owner_ref is None
                or timing_owner_ref() is not timing_planner
            ):
                raise EventContractError("Persistent SMB certification has stale source timing")
            existing_receipt = member.commit_receipt
            group_id = group.facts.group_id
            member_id = facts.member_id

        if not timing_planner.authenticates_committed_detached_preparation_binding(
            binding,
            certification_snapshot.expected_timing_receipt,
            context_digest=facts.timing_context_digest,
        ):
            if timing_planner.authenticates_expected_detached_preparation_binding(
                binding,
                certification_snapshot.expected_timing_receipt,
                context_digest=facts.timing_context_digest,
            ):
                raise EventContractError("Persistent SMB source timing is not committed")
            raise EventContractError("Persistent SMB source timing is foreign, tampered, or stale")

        if existing_receipt is not None:
            receipt_snapshot = self._snapshot_commit_receipt(existing_receipt)
            if receipt_snapshot is None or not self._commit_receipt_facts_match(
                receipt_snapshot,
                facts,
                certification_snapshot,
            ):
                raise EventContractError("Persistent SMB committed receipt is tampered or stale")
            with self._lock:
                retained = self._member_for_certification_locked(certification)
                if (
                    retained is None
                    or retained[0] is not group
                    or retained[1] is not member
                    or member.state != "committed_unacknowledged"
                    or member.commit_receipt is not existing_receipt
                ):
                    raise EventContractError("Persistent SMB committed member changed or is stale")
                return existing_receipt

        integrity = self._commit_receipt_integrity(
            member=facts,
            certification=certification_snapshot,
        )
        receipt = PersistentSmbProjectionMemberCommitReceipt(
            dispatcher_id=facts.dispatcher_id,
            group_id=facts.group_id,
            generation_id=facts.generation_id,
            member_id=facts.member_id,
            member_ordinal=facts.member_ordinal,
            phase=facts.phase,
            operation_id=facts.operation_id,
            operation_binding_digest=facts.operation_binding_digest,
            capsule_digest=facts.capsule_digest,
            timing_context_digest=facts.timing_context_digest,
            timing_receipt_digest=certification_snapshot.timing_receipt_digest,
            topology_generation_digest=certification_snapshot.topology_generation_digest,
            target_formats=certification_snapshot.target_formats,
            lifecycle_binding_digest=certification_snapshot.lifecycle_binding_digest,
            lifecycle_binding_generation=certification_snapshot.lifecycle_binding_generation,
            network_binding_digest=certification_snapshot.network_binding_digest,
            network_binding_generation=certification_snapshot.network_binding_generation,
            traffic_binding_digest=certification_snapshot.traffic_binding_digest,
            traffic_binding_generation=certification_snapshot.traffic_binding_generation,
            state="committed_unacknowledged",
            _integrity=integrity,
        )
        with self._lock:
            retained_group = self._groups.get(group_id)
            retained = retained_group.members.get(member_id) if retained_group is not None else None
            if (
                retained_group is not group
                or retained is not member
                or retained.state != "certified"
                or retained.certification is not certification
                or retained.commit_receipt is not None
                or retained.timing_binding is not binding
                or retained.timing_owner_ref is not timing_owner_ref
                or timing_owner_ref() is not timing_planner
            ):
                if (
                    retained is member
                    and retained.state == "committed_unacknowledged"
                    and retained.commit_receipt is not None
                ):
                    return retained.commit_receipt
                raise EventContractError("Persistent SMB member changed during commit")
            maps_before = self._dict_backing_bytes(self._commit_receipt_locators)
            try:
                self._commit_receipt_locators[id(receipt)] = (group_id, member_id)
            except BaseException:
                self._commit_receipt_locators.pop(id(receipt), None)
                self._record_table_delta_locked(
                    maps_before,
                    self._dict_backing_bytes(self._commit_receipt_locators),
                )
                raise
            self._record_table_delta_locked(
                maps_before,
                self._dict_backing_bytes(self._commit_receipt_locators),
            )
            member.commit_receipt = receipt
            member.state = "committed_unacknowledged"
            self._certified_members -= 1
            self._committed_unacknowledged_members += 1
            self._retained_commit_receipts += 1
            self._high_water_committed_unacknowledged_members = max(
                self._high_water_committed_unacknowledged_members,
                self._committed_unacknowledged_members,
            )
            self._high_water_commit_receipts = max(
                self._high_water_commit_receipts,
                self._retained_commit_receipts,
            )
            return receipt

    def recover_committed_member(
        self,
        group: PersistentSmbProjectionGroupToken,
        *,
        operation_id: str,
        operation_binding_digest: str,
        timing_planner: SourceTimingPlanner,
    ) -> PersistentSmbProjectionCommittedMemberRecovery:
        """Resolve one exact same-operation committed lost return in O(1)."""

        if type(group) is not PersistentSmbProjectionGroupToken:
            raise EventContractError("Persistent SMB projection group is foreign, copied, or stale")
        operation = _bounded_text(
            operation_id,
            "persistent SMB operation id",
            _MAX_OPERATION_ID_UTF8_BYTES,
        )
        owner_digest = _sha256_hex(
            operation_binding_digest,
            "persistent SMB operation binding digest",
        )
        if type(timing_planner) is not SourceTimingPlanner:
            raise EventContractError("Persistent SMB timing planner requires its exact owner type")
        with self._lock:
            retained_group = self._group_for_token_locked(group)
            if retained_group is None:
                raise EventContractError(
                    "Persistent SMB committed recovery is foreign, copied, or stale"
                )
            member_id = retained_group.member_by_operation.get(operation)
            member = retained_group.members.get(member_id) if member_id is not None else None
            if member is None or member.state != "committed_unacknowledged":
                raise EventContractError("Persistent SMB operation is not committed")
            facts = member.facts
            certification = member.certification
            receipt = member.commit_receipt
            binding = member.timing_binding
            timing_owner_ref = member.timing_owner_ref
            if (
                facts is None
                or facts.operation_binding_digest != owner_digest
                or certification is None
                or receipt is None
                or binding is None
                or timing_owner_ref is None
                or timing_owner_ref() is not timing_planner
            ):
                raise EventContractError("Persistent SMB committed recovery is tampered or stale")

        certification_snapshot = self._snapshot_certification(certification)
        receipt_snapshot = self._snapshot_commit_receipt(receipt)
        if (
            certification_snapshot is None
            or receipt_snapshot is None
            or not self._certification_facts_match(certification_snapshot, facts)
            or not self._commit_receipt_facts_match(
                receipt_snapshot,
                facts,
                certification_snapshot,
            )
            or not timing_planner.authenticates_committed_detached_preparation_binding(
                binding,
                certification_snapshot.expected_timing_receipt,
                context_digest=facts.timing_context_digest,
            )
        ):
            raise EventContractError("Persistent SMB committed recovery is tampered or stale")
        with self._lock:
            current_group = self._group_for_token_locked(group)
            current = current_group.members.get(member_id) if current_group is not None else None
            if (
                current_group is not retained_group
                or current is not member
                or current.state != "committed_unacknowledged"
                or current.commit_receipt is not receipt
                or current.certification is not certification
                or current.timing_binding is not binding
            ):
                raise EventContractError("Persistent SMB committed recovery changed or is stale")
            return PersistentSmbProjectionCommittedMemberRecovery(
                commit_receipt=receipt,
                state="committed_unacknowledged",
            )

    def acknowledge_member(
        self,
        receipt: PersistentSmbProjectionMemberCommitReceipt,
        *,
        expected_generation_id: str,
        timing_planner: SourceTimingPlanner,
    ) -> bool:
        """Generation-CAS acknowledge one exact durable member handoff."""

        if type(timing_planner) is not SourceTimingPlanner:
            return False
        try:
            generation = _sha256_hex(
                expected_generation_id,
                "persistent SMB expected generation id",
            )
        except EventContractError:
            return False
        receipt_snapshot = self._snapshot_commit_receipt(receipt)
        if receipt_snapshot is None or receipt_snapshot.generation_id != generation:
            return False
        with self._lock:
            located = self._member_for_commit_receipt_locked(receipt)
            if located is None:
                return False
            group, member = located
            if member.state != "committed_unacknowledged":
                return False
            facts = member.facts
            certification = member.certification
            binding = member.timing_binding
            timing_owner_ref = member.timing_owner_ref
            if (
                facts is None
                or certification is None
                or binding is None
                or timing_owner_ref is None
                or timing_owner_ref() is not timing_planner
                or facts.generation_id != generation
            ):
                return False
            group_id = group.facts.group_id
            member_id = facts.member_id
        certification_snapshot = self._snapshot_certification(certification)
        if (
            certification_snapshot is None
            or not self._certification_facts_match(certification_snapshot, facts)
            or not self._commit_receipt_facts_match(
                receipt_snapshot,
                facts,
                certification_snapshot,
            )
            or not timing_planner.authenticates_committed_detached_preparation_binding(
                binding,
                certification_snapshot.expected_timing_receipt,
                context_digest=facts.timing_context_digest,
            )
        ):
            return False
        with self._lock:
            current_group = self._groups.get(group_id)
            current = current_group.members.get(member_id) if current_group is not None else None
            if (
                current_group is not group
                or current is not member
                or current.state != "committed_unacknowledged"
                or current.commit_receipt is not receipt
                or current.certification is not certification
                or current.timing_binding is not binding
                or current.timing_owner_ref is not timing_owner_ref
                or timing_owner_ref() is not timing_planner
            ):
                return False
            member.state = "acknowledging"
        try:
            timing_planner.discard_detached_preparation_binding(binding)
        except BaseException:
            with self._lock:
                current_group = self._groups.get(group_id)
                current = (
                    current_group.members.get(member_id) if current_group is not None else None
                )
                if current is member and current.state == "acknowledging":
                    current.state = "committed_unacknowledged"
            raise
        with self._lock:
            current_group = self._groups.get(group_id)
            current = current_group.members.get(member_id) if current_group is not None else None
            if (
                current_group is not group
                or current is not member
                or current.state != "acknowledging"
            ):
                raise EventContractError("Persistent SMB member changed during acknowledgement")
            self._remove_member_locked(current_group, current)
            return True

    def recover_inactive_member(
        self,
        group: PersistentSmbProjectionGroupToken,
        *,
        operation_id: str,
        operation_binding_digest: str,
        timing_planner: SourceTimingPlanner,
    ) -> PersistentSmbProjectionMemberRecovery:
        """Resolve one exact same-operation inactive lost return in O(1)."""

        if type(group) is not PersistentSmbProjectionGroupToken:
            raise EventContractError("Persistent SMB projection group is foreign, copied, or stale")
        operation = _bounded_text(
            operation_id,
            "persistent SMB operation id",
            _MAX_OPERATION_ID_UTF8_BYTES,
        )
        owner_digest = _sha256_hex(
            operation_binding_digest,
            "persistent SMB operation binding digest",
        )
        if type(timing_planner) is not SourceTimingPlanner:
            raise EventContractError("Persistent SMB timing planner requires its exact owner type")

        with self._lock:
            retained_group = self._group_for_token_locked(group)
            if retained_group is None:
                raise EventContractError(
                    "Persistent SMB operation recovery is foreign, copied, or stale"
                )
            member_id = retained_group.member_by_operation.get(operation)
            member = retained_group.members.get(member_id) if member_id is not None else None
            facts = member.facts if member is not None else None
            if member is None or facts is None or member.state != "inactive":
                raise EventContractError("Persistent SMB operation is not an inactive member")
            if facts.operation_binding_digest != owner_digest:
                raise EventContractError(
                    "Persistent SMB operation recovery has a foreign operation binding"
                )
            token = member.token
            binding = member.timing_binding
            timing_owner_ref = member.timing_owner_ref
            if timing_owner_ref is None:
                raise EventContractError(
                    "Persistent SMB operation recovery lost its timing binding owner"
                )
            timing_owner = timing_owner_ref()
            if timing_owner is None:
                self._remove_member_locked(retained_group, member)
                raise EventContractError(
                    "Persistent SMB operation recovery reclaimed a collected timing owner"
                )
            if timing_owner is not timing_planner:
                raise EventContractError(
                    "Persistent SMB operation recovery has a stale timing binding owner"
                )
            if token is None or binding is None:
                raise EventContractError("Persistent SMB operation recovery is tampered or stale")
            context_digest = facts.timing_context_digest

        token_snapshot = self._snapshot_member_token(token)
        if token_snapshot is None or token_snapshot[1] is not binding:
            raise EventContractError("Persistent SMB operation recovery is tampered or stale")
        with self._lock:
            initial_group = self._group_for_token_locked(group)
            initial_member = (
                initial_group.members.get(member_id) if initial_group is not None else None
            )
            if (
                initial_group is not retained_group
                or initial_member is not member
                or initial_group.member_by_operation.get(operation) != member_id
                or initial_member.state != "inactive"
                or initial_member.token is not token
                or initial_member.timing_binding is not binding
                or initial_member.timing_owner_ref is not timing_owner_ref
                or timing_owner_ref() is not timing_planner
                or initial_member.facts is not facts
                or not self._member_facts_match(token_snapshot[0], facts)
            ):
                raise EventContractError(
                    "Persistent SMB operation recovery changed or became stale"
                )

        if not timing_planner.authenticates_detached_preparation_binding(
            binding,
            context_digest=context_digest,
        ):
            raise EventContractError("Persistent SMB operation recovery has a stale timing binding")

        final_snapshot = self._snapshot_member_token(token)
        if final_snapshot is None or final_snapshot[1] is not binding:
            raise EventContractError("Persistent SMB operation recovery changed or became stale")
        with self._lock:
            final_group = self._group_for_token_locked(group)
            final_member = final_group.members.get(member_id) if final_group is not None else None
            final_facts = final_member.facts if final_member is not None else None
            if (
                final_group is not retained_group
                or final_member is not member
                or final_member.state != "inactive"
                or final_member.token is not token
                or final_member.timing_binding is not binding
                or final_member.timing_owner_ref is not timing_owner_ref
                or timing_owner_ref() is not timing_planner
                or final_facts is not facts
                or not self._member_facts_match(final_snapshot[0], facts)
            ):
                raise EventContractError(
                    "Persistent SMB operation recovery changed or became stale"
                )
            return PersistentSmbProjectionMemberRecovery(
                member_token=token,
                state="inactive",
            )

    def cancel_member(
        self,
        token: PersistentSmbProjectionMemberToken,
        *,
        timing_planner: SourceTimingPlanner,
    ) -> None:
        """Cancel one exact inactive or uncommitted certified member."""

        if type(token) is not PersistentSmbProjectionMemberToken:
            raise EventContractError("Persistent SMB member is foreign, copied, or stale")
        with self._lock:
            located = self._member_for_token_locked(token)
            if located is None or located[1].state not in {"inactive", "certified"}:
                raise EventContractError("Persistent SMB member is foreign, copied, or stale")
            group, member = located
            original_state = member.state
            binding = member.timing_binding
            if binding is None:
                raise EventContractError("Inactive persistent SMB member lost its timing binding")
            timing_owner_ref = member.timing_owner_ref
            if timing_owner_ref is None:
                raise EventContractError("Inactive persistent SMB member lost its timing owner")
            timing_owner = timing_owner_ref()
            if timing_owner is None:
                self._remove_member_locked(group, member)
                return
            if type(timing_planner) is not SourceTimingPlanner:
                raise EventContractError(
                    "Persistent SMB timing planner requires its exact owner type"
                )
            if timing_owner is not timing_planner:
                raise EventContractError(
                    "Persistent SMB timing planner is foreign, collected, or stale"
                )
            group_id = group.facts.group_id
            member_id = member.reservation.member_id
            context_digest = member.facts.timing_context_digest if member.facts is not None else ""
            if not context_digest:
                raise EventContractError("Inactive persistent SMB member lost its timing context")
            member.state = f"cancelling_{original_state}"
        try:
            timing_planner.discard_detached_preparation_binding(binding)
        except StateError:
            if timing_planner.authenticates_detached_preparation_binding(
                binding,
                context_digest=context_digest,
            ):
                with self._lock:
                    retained_group = self._groups.get(group_id)
                    retained = (
                        retained_group.members.get(member_id)
                        if retained_group is not None
                        else None
                    )
                    if retained is member and retained.state == f"cancelling_{original_state}":
                        retained.state = original_state
                raise
        except BaseException:
            with self._lock:
                retained_group = self._groups.get(group_id)
                retained = (
                    retained_group.members.get(member_id) if retained_group is not None else None
                )
                if retained is member and retained.state == f"cancelling_{original_state}":
                    retained.state = original_state
            raise
        with self._lock:
            retained_group = self._groups.get(group_id)
            retained = retained_group.members.get(member_id) if retained_group is not None else None
            if (
                retained_group is not group
                or retained is not member
                or member.state != f"cancelling_{original_state}"
            ):
                raise EventContractError("Persistent SMB member changed during cancellation")
            self._remove_member_locked(retained_group, retained)

    def cancel_empty_group(self, group: PersistentSmbProjectionGroupToken) -> None:
        """Reclaim one exact empty group and its declared future reservations."""

        if type(group) is not PersistentSmbProjectionGroupToken:
            raise EventContractError("Persistent SMB projection group is foreign, copied, or stale")
        with self._lock:
            retained = self._group_for_token_locked(group)
            if retained is None or retained.members:
                raise EventContractError(
                    "Persistent SMB projection group is foreign, copied, nonempty, or stale"
                )
            facts = retained.facts
            maps_before = self._dict_backing_bytes(
                self._groups,
                self._group_token_locators,
                retained.members,
                retained.member_by_operation,
            )
            self._groups.pop(facts.group_id, None)
            self._group_token_locators.pop(id(group), None)
            if not self._groups:
                self._groups.clear()
            if not self._group_token_locators:
                self._group_token_locators.clear()
            retained.members.clear()
            retained.member_by_operation.clear()
            maps_after = self._dict_backing_bytes(
                self._groups,
                self._group_token_locators,
            )
            self._record_table_delta_locked(maps_before, maps_after)
            self._retained_group_bytes -= retained.base_retained_bytes
            self._retained_bytes -= retained.retained_bytes
            self._reserved_member_capacity -= facts.member_budget
            self._reserved_receipt_capacity -= facts.member_budget
            self._reserved_byte_capacity -= facts.byte_budget
            retained.state = "cancelled"

    def census(
        self,
        *,
        estimate_bytes: bool = False,
    ) -> PersistentSmbProjectionGroupCensus:
        """Return constant-time counts and optional exact table estimates."""

        if type(estimate_bytes) is not bool:
            raise EventContractError("estimate_bytes requires an exact bool")
        with self._lock:
            entry_semantic_bytes = self._retained_bytes if estimate_bytes else 0
            table_backing_bytes = self._table_backing_bytes if estimate_bytes else 0
            return PersistentSmbProjectionGroupCensus(
                retained_groups=len(self._groups),
                inactive_members=self._inactive_members,
                certified_members=self._certified_members,
                committed_unacknowledged_members=(self._committed_unacknowledged_members),
                retained_commit_receipts=self._retained_commit_receipts,
                retained_bytes=self._retained_bytes,
                reserved_member_capacity=self._reserved_member_capacity,
                reserved_receipt_capacity=self._reserved_receipt_capacity,
                reserved_byte_capacity=self._reserved_byte_capacity,
                group_capacity=self._group_capacity,
                member_capacity=self._member_capacity,
                receipt_capacity=self._receipt_capacity,
                byte_capacity=self._byte_capacity,
                high_water_groups=self._high_water_groups,
                high_water_members=self._high_water_members,
                high_water_certified_members=self._high_water_certified_members,
                high_water_committed_unacknowledged_members=(
                    self._high_water_committed_unacknowledged_members
                ),
                high_water_commit_receipts=self._high_water_commit_receipts,
                high_water_bytes=self._high_water_bytes,
                high_water_table_backing_bytes=self._high_water_table_backing_bytes,
                retained_target_generations=0,
                target_generation_capacity=0,
                high_water_target_generations=0,
                target_generation_semantic_bytes=0,
                target_generation_table_backing_bytes=0,
                high_water_target_generation_table_backing_bytes=0,
                entry_semantic_bytes=entry_semantic_bytes,
                table_backing_bytes=table_backing_bytes,
                estimated_bytes=entry_semantic_bytes + table_backing_bytes,
            )

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Inert bounded retention for persistent-SMB detached projection facts.

The authority in this module stops at an inactive, recoverable reservation. It
retains one immutable primitive capsule and one exact detached source-timing
binding per member, plus a non-owning exact timing-owner locator. It never
retains a prepared dispatch, source-timing
preparation, canonical occurrence graph, manager, emitter, or callback.

The opaque operation-binding digest is only a future coordinator boundary. This
module does not authenticate an SMB manager result and deliberately exposes no
activation, certification, committed receipt, acknowledgement, close, or
publication API. Source capability allowlisting, including any future Syslog
support, belongs to the separately reviewed terminal integration. This slice
integrates no source allowlist, and Syslog is unsupported.
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
)
from evidenceforge.models.exceptions import EventContractError, StateError

_MAX_OPERATION_ID_UTF8_BYTES = 512
_MAX_PROJECTION_CAPSULE_BYTES = 4 * 1024 * 1024
_MAX_CAPSULE_PARTS = 16_384
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
class PersistentSmbProjectionGroupCensus:
    """Constant-time live-retention and declared-reservation accounting."""

    retained_groups: int
    inactive_members: int
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
        self._inactive_members = 0
        self._retained_bytes = 0
        self._retained_group_bytes = 0
        self._reserved_member_capacity = 0
        self._reserved_receipt_capacity = 0
        self._reserved_byte_capacity = 0
        self._high_water_groups = 0
        self._high_water_members = 0
        self._high_water_bytes = 0
        self._table_backing_bytes = self._dict_backing_bytes(
            self._groups,
            self._group_token_locators,
            self._member_token_locators,
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
        """Remove one trusted preparing/inactive member and all live charges."""

        member_id = member.reservation.member_id
        operation = member.reservation.operation_id
        token = member.token
        maps_before = self._dict_backing_bytes(
            group.members,
            group.member_by_operation,
            self._member_token_locators,
        )
        if token is not None:
            locator = self._member_token_locators.get(id(token))
            if locator == (group.facts.group_id, member_id):
                self._member_token_locators.pop(id(token), None)
        group.members.pop(member_id, None)
        if group.member_by_operation.get(operation) == member_id:
            group.member_by_operation.pop(operation, None)
        if not group.members:
            group.members.clear()
        if not group.member_by_operation:
            group.member_by_operation.clear()
        if not self._member_token_locators:
            self._member_token_locators.clear()
        maps_after = self._dict_backing_bytes(
            group.members,
            group.member_by_operation,
            self._member_token_locators,
        )
        self._record_table_delta_locked(maps_before, maps_after)
        group.member_bytes -= member.retained_bytes
        group.retained_bytes -= member.retained_bytes
        self._retained_bytes -= member.retained_bytes
        self._inactive_members -= 1
        member.token = None
        member.capsule = None
        member.facts = None
        member.timing_binding = None
        member.timing_owner_ref = None
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
                raise EventContractError("Persistent SMB operation recovery is tampered or stale")
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
        """Cancel one exact inactive member and reclaim every live charge."""

        if type(token) is not PersistentSmbProjectionMemberToken:
            raise EventContractError("Persistent SMB member is foreign, copied, or stale")
        with self._lock:
            located = self._member_for_token_locked(token)
            if located is None or located[1].state != "inactive":
                raise EventContractError("Persistent SMB member is foreign, copied, or stale")
            group, member = located
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
            member.state = "cancelling"
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
                    if retained is member and retained.state == "cancelling":
                        retained.state = "inactive"
                raise
        except BaseException:
            with self._lock:
                retained_group = self._groups.get(group_id)
                retained = (
                    retained_group.members.get(member_id) if retained_group is not None else None
                )
                if retained is member and retained.state == "cancelling":
                    retained.state = "inactive"
            raise
        with self._lock:
            retained_group = self._groups.get(group_id)
            retained = retained_group.members.get(member_id) if retained_group is not None else None
            if (
                retained_group is not group
                or retained is not member
                or member.state != "cancelling"
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

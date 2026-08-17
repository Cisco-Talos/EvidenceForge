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

"""Prepared generator-local state for one canonical network transaction.

The runtime owns only planner caches and compatibility observations that are
local to the canonical network root.  StateManager, lifecycle, dispatch, and
application-channel publication remain separate authenticated authorities.
Preparations reserve exact point keys, plan against copy-on-write values, and
publish those points only through a short, prevalidated no-fail commit.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import random
import secrets
from collections.abc import Hashable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, fields, replace
from datetime import UTC, datetime, timedelta
from enum import Enum, StrEnum
from threading import RLock
from typing import Any, Literal

from evidenceforge.events.contexts import (
    FileTransferContext,
    HttpContext,
    HttpEntityPartContext,
    HttpMultipartEntityContext,
    HttpRequestEntityContext,
    HttpWireSpanContext,
)
from evidenceforge.events.cryptography import (
    CertificateAuthorityMaterial,
    CertificateIdentityPlan,
)
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.generation.cryptographic_material import (
    CryptographicMaterialPreparation,
    CryptographicMaterialPreparationReceipt,
    CryptographicMaterialPreparationToken,
    CryptographicMaterialPreparedCommit,
    CryptographicMaterialRegistry,
)
from evidenceforge.generation.state_manager import (
    ConnectionCompositeMaterializationPlan,
    ConnectionIdentityPlan,
    ConnectionMaterializationMode,
    ConnectionPlanningCursor,
    MaterializationBatchPlan,
    ProcessActivityPatch,
    SessionActivityPatch,
    StateManager,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc

_MAX_TIME = datetime.max.replace(tzinfo=UTC)
_MIN_TIME = datetime.min.replace(tzinfo=UTC)
_MISSING_DIGEST = hashlib.sha256(b"network-runtime:missing").hexdigest()

NetworkTransportLifecycleMode = Literal["network", "deferred_session", "application_child"]
_DeferredCompositionKind = Literal["ssh", "rdp"]


def _canonical_datetime(value: datetime, *, field_name: str) -> datetime:
    """Return one exact datetime without invoking caller-defined subclasses."""

    if type(value) is not datetime:
        raise ValueError(f"Network runtime {field_name} must be an exact datetime")
    return ensure_utc(value)


class NetworkRuntimePointFamily(StrEnum):
    """Exact-key planner state owned by the canonical network runtime."""

    RECENT_TUPLE = "recent_tuple"
    ICMP_OBSERVATION = "icmp_observation"
    DIRECT_DNS_TTL = "direct_dns_ttl"
    DNS_OBSERVATION = "dns_observation"
    TLS_SERVER_NAME = "tls_server_name"
    TLS_CLIENT_SERVER_PAIR = "tls_client_server_pair"
    NTP_ASSOCIATION = "ntp_association"
    NTP_SERVER_PROFILE = "ntp_server_profile"
    NTP_PARSER = "ntp_parser"
    RESPONDER_BINDING = "responder_binding"


def _canonical_family(family: NetworkRuntimePointFamily) -> NetworkRuntimePointFamily:
    """Return one exact public point family before any authority mutation."""

    if type(family) is not NetworkRuntimePointFamily:
        raise ValueError("Network runtime points require a typed point family")
    return family


def _point_key_order(point_key: _PointKey) -> tuple[str, str]:
    """Return the deterministic order for one already-canonical point key."""

    family, key = point_key
    return _canonical_family(family).value, repr(_freeze_digest_value(key))


def _canonical_point_key(value: object) -> _PointKey:
    """Return one exact typed point-key pair from a caller-owned overlay map."""

    if type(value) is not tuple or len(value) != 2:
        raise StateError("Network runtime preparation contains an invalid point key")
    return _canonical_family(value[0]), _canonical_key(value[1])


_PointKey = tuple[NetworkRuntimePointFamily, Hashable]
_ExpiryKind = Literal["live", "tombstone"]
_ExpiryEntry = tuple[
    datetime,
    int,
    NetworkRuntimePointFamily,
    Hashable,
    int,
    _ExpiryKind,
]


def _expiry_point_key(entry: _ExpiryEntry) -> _PointKey:
    return entry[2], entry[3]


def _expiry_order(entry: _ExpiryEntry) -> tuple[datetime, int]:
    return entry[0], entry[1]


class _IndexedExpiryHeap:
    """Exact-key removable deadline heap with O(log n) point replacement."""

    __slots__ = ("_entries", "_positions")

    def __init__(self) -> None:
        self._entries: list[_ExpiryEntry] = []
        self._positions: dict[_PointKey, int] = {}

    def __bool__(self) -> bool:
        return bool(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def first(self) -> _ExpiryEntry:
        if not self._entries:
            raise StateError("Network runtime deadline heap is empty")
        return self._entries[0]

    def pop_first(self) -> _ExpiryEntry:
        """Remove and return the deterministic earliest deadline."""

        if not self._entries:
            raise StateError("Network runtime deadline heap is empty")
        return self._remove_at(0)

    def replace(self, point_key: _PointKey, entry: _ExpiryEntry | None) -> None:
        """Install or remove one point deadline without scanning other points."""

        position = self._positions.get(point_key)
        if entry is None:
            if position is not None:
                self._remove_at(position)
            return
        if _expiry_point_key(entry) != point_key:
            raise StateError("Network runtime deadline point identity diverged")
        if position is None:
            position = len(self._entries)
            self._entries.append(entry)
            self._positions[point_key] = position
            self._sift_up(position)
            return
        prior = self._entries[position]
        self._entries[position] = entry
        if _expiry_order(entry) < _expiry_order(prior):
            self._sift_up(position)
        else:
            self._sift_down(position)

    def _remove_at(self, position: int) -> _ExpiryEntry:
        removed = self._entries[position]
        removed_key = _expiry_point_key(removed)
        last = self._entries.pop()
        self._positions.pop(removed_key)
        if position == len(self._entries):
            return removed
        self._entries[position] = last
        self._positions[_expiry_point_key(last)] = position
        if position and _expiry_order(last) < _expiry_order(self._entries[(position - 1) // 2]):
            self._sift_up(position)
        else:
            self._sift_down(position)
        return removed

    def _sift_up(self, position: int) -> None:
        while position:
            parent = (position - 1) // 2
            if _expiry_order(self._entries[parent]) <= _expiry_order(self._entries[position]):
                return
            self._swap(parent, position)
            position = parent

    def _sift_down(self, position: int) -> None:
        size = len(self._entries)
        while True:
            left = position * 2 + 1
            if left >= size:
                return
            right = left + 1
            child = left
            if right < size and _expiry_order(self._entries[right]) < _expiry_order(
                self._entries[left]
            ):
                child = right
            if _expiry_order(self._entries[position]) <= _expiry_order(self._entries[child]):
                return
            self._swap(position, child)
            position = child

    def _swap(self, left: int, right: int) -> None:
        self._entries[left], self._entries[right] = self._entries[right], self._entries[left]
        self._positions[_expiry_point_key(self._entries[left])] = left
        self._positions[_expiry_point_key(self._entries[right])] = right


class _IndexedPreparationFenceHeap:
    """Exact preparation-id minimum fence with O(log n) replacement/removal."""

    __slots__ = ("_entries", "_positions")

    def __init__(self) -> None:
        self._entries: list[tuple[datetime, int]] = []
        self._positions: dict[int, int] = {}

    def __bool__(self) -> bool:
        return bool(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def first_deadline(self) -> datetime:
        if not self._entries:
            raise StateError("Network runtime preparation fence heap is empty")
        return self._entries[0][0]

    def set(self, preparation_id: int, deadline: datetime) -> None:
        entry = (deadline, preparation_id)
        position = self._positions.get(preparation_id)
        if position is None:
            position = len(self._entries)
            self._entries.append(entry)
            self._positions[preparation_id] = position
            self._sift_up(position)
            return
        prior = self._entries[position]
        self._entries[position] = entry
        if entry < prior:
            self._sift_up(position)
        else:
            self._sift_down(position)

    def remove(self, preparation_id: int) -> None:
        position = self._positions.get(preparation_id)
        if position is None:
            return
        last = self._entries.pop()
        self._positions.pop(preparation_id)
        if position == len(self._entries):
            return
        self._entries[position] = last
        self._positions[last[1]] = position
        if position and last < self._entries[(position - 1) // 2]:
            self._sift_up(position)
        else:
            self._sift_down(position)

    def _sift_up(self, position: int) -> None:
        while position:
            parent = (position - 1) // 2
            if self._entries[parent] <= self._entries[position]:
                return
            self._swap(parent, position)
            position = parent

    def _sift_down(self, position: int) -> None:
        size = len(self._entries)
        while True:
            left = position * 2 + 1
            if left >= size:
                return
            right = left + 1
            child = right if right < size and self._entries[right] < self._entries[left] else left
            if self._entries[position] <= self._entries[child]:
                return
            self._swap(position, child)
            position = child

    def _swap(self, left: int, right: int) -> None:
        self._entries[left], self._entries[right] = self._entries[right], self._entries[left]
        self._positions[self._entries[left][1]] = left
        self._positions[self._entries[right][1]] = right


def _freeze_digest_value(value: object, active: set[int] | None = None) -> object:
    """Return a deterministic, cycle-safe digest preimage for retained values."""

    if active is None:
        active = set()
    if value is None:
        return ("none",)
    if type(value) is bool:
        return ("bool", value)
    if type(value) is int:
        return ("int", value)
    if type(value) is float:
        return ("float", value.hex())
    if type(value) is str:
        return ("str", value)
    if type(value) is bytes:
        return ("bytes", value.hex())
    if type(value) is datetime:
        if value.tzinfo is not UTC:
            raise ValueError("Network runtime datetimes must use exact UTC timezone identity")
        return ("datetime", value.isoformat())
    if type(value) is timedelta:
        return ("timedelta", value.days, value.seconds, value.microseconds)

    identity = id(value)
    if identity in active:
        raise StateError("Network runtime values cannot contain reference cycles")
    active.add(identity)
    try:
        if type(value) is tuple:
            return ("tuple", tuple(_freeze_digest_value(item, active) for item in value))
        if type(value) is list:
            return ("list", tuple(_freeze_digest_value(item, active) for item in value))
        if type(value) in {set, frozenset}:
            frozen = [_freeze_digest_value(item, active) for item in value]
            return (
                "frozenset" if type(value) is frozenset else "set",
                tuple(sorted(frozen, key=repr)),
            )
        if type(value) is dict:
            frozen_items = [
                (
                    _freeze_digest_value(key, active),
                    _freeze_digest_value(item, active),
                )
                for key, item in value.items()
            ]
            return ("dict", tuple(sorted(frozen_items, key=lambda item: repr(item[0]))))
        if type(value) in _CANONICAL_EVENT_DATACLASSES:
            return (
                "dataclass",
                f"{value.__class__.__module__}.{value.__class__.__qualname__}",
                tuple(
                    (member.name, _freeze_digest_value(getattr(value, member.name), active))
                    for member in fields(value)
                ),
            )
        raise ValueError(
            "Network runtime retained values must use deterministic primitives, "
            "containers or canonical event dataclasses; got "
            f"{value.__class__.__module__}.{value.__class__.__qualname__}"
        )
    finally:
        active.remove(identity)


def _value_digest(value: object) -> str:
    return hashlib.sha256(repr(_freeze_digest_value(value)).encode()).hexdigest()


def _validate_retained_tree(
    value: object,
    *,
    allow_mutable_containers: bool,
    for_key: bool = False,
    active: set[int] | None = None,
) -> None:
    """Reject retained values with user-defined copy/hash/representation behavior."""

    if active is None:
        active = set()
    if value is None or type(value) in {int, str, bytes}:
        return
    if type(value) is bool:
        if for_key:
            raise ValueError("Network runtime point keys cannot contain booleans")
        return
    if type(value) is float:
        if for_key:
            raise ValueError("Network runtime point keys cannot contain floats")
        return
    if type(value) is datetime:
        if value.tzinfo is not UTC:
            raise ValueError("Network runtime retained datetimes must use exact UTC")
        return
    if type(value) is timedelta:
        return
    if isinstance(value, Enum):
        raise ValueError(
            "Network runtime retained points require inert primitive enum values, "
            "not Enum instances"
        )
    identity = id(value)
    if identity in active:
        raise StateError("Network runtime retained values cannot contain reference cycles")
    active.add(identity)
    try:
        if type(value) in {tuple, frozenset}:
            for item in value:  # type: ignore[union-attr]
                _validate_retained_tree(
                    item,
                    allow_mutable_containers=allow_mutable_containers,
                    for_key=for_key,
                    active=active,
                )
            return
        if allow_mutable_containers and type(value) in {list, set}:
            for item in value:  # type: ignore[union-attr]
                _validate_retained_tree(
                    item,
                    allow_mutable_containers=True,
                    for_key=for_key,
                    active=active,
                )
            return
        if allow_mutable_containers and type(value) is dict:
            for key, item in value.items():  # type: ignore[union-attr]
                _validate_retained_tree(
                    key,
                    allow_mutable_containers=False,
                    for_key=True,
                    active=active,
                )
                _validate_retained_tree(
                    item,
                    allow_mutable_containers=True,
                    for_key=for_key,
                    active=active,
                )
            return
        raise ValueError(
            "Network runtime retained points support only deterministic primitives and "
            f"built-in containers; got {value.__class__.__module__}."
            f"{value.__class__.__qualname__}"
        )
    finally:
        active.remove(identity)


def _canonical_key(key: Hashable) -> Hashable:
    try:
        hash(key)
        canonical = copy.deepcopy(key)
        hash(canonical)
    except (copy.Error, AttributeError, TypeError, ValueError) as exc:
        raise ValueError(
            "Network runtime point keys must support an exact immutable, hashable copy"
        ) from exc
    _validate_retained_tree(canonical, allow_mutable_containers=False, for_key=True)
    _freeze_digest_value(canonical)
    return canonical


def _canonical_value(value: object) -> object:
    try:
        canonical = copy.deepcopy(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("Network runtime point values must support an exact frozen copy") from exc
    _validate_retained_tree(canonical, allow_mutable_containers=True)
    _freeze_digest_value(canonical)
    return canonical


def _validate_canonical_event_tree(
    value: object,
    *,
    active: set[int] | None = None,
) -> None:
    """Reject custom copy/access behavior from a prepared commit result."""

    if active is None:
        active = set()
    if value is None or type(value) in {bool, int, float, str, bytes}:
        return
    if type(value) is datetime:
        if value.tzinfo is not UTC:
            raise StateError("Network commit result datetimes must use exact UTC")
        return
    if type(value) is timedelta:
        return
    if isinstance(value, Enum):
        raise StateError("Network commit result contains an unsupported enum")
    identity = id(value)
    if identity in active:
        raise StateError("Network commit result cannot contain reference cycles")
    active.add(identity)
    try:
        if type(value) is tuple:
            for item in value:  # type: ignore[union-attr]
                _validate_canonical_event_tree(item, active=active)
            return
        if type(value) in _CANONICAL_EVENT_DATACLASSES:
            for member in fields(value):
                _validate_canonical_event_tree(getattr(value, member.name), active=active)
            return
        raise StateError(
            "Network commit result contains an unsupported value of type "
            f"{value.__class__.__module__}.{value.__class__.__qualname__}"
        )
    finally:
        active.remove(identity)


def _canonical_commit_result(
    result: NetworkConnectionCommitResult,
) -> NetworkConnectionCommitResult:
    """Freeze the sole trusted commit-result snapshot before nested sealing."""

    _validate_canonical_event_tree(result)
    try:
        canonical = copy.deepcopy(result)
    except (copy.Error, AttributeError, TypeError, ValueError) as exc:
        raise StateError("Network commit result cannot be frozen exactly") from exc
    if type(canonical) is not NetworkConnectionCommitResult:
        raise StateError("Network commit result changed type during canonicalization")
    _validate_canonical_event_tree(canonical)
    _freeze_digest_value(canonical)
    return canonical


@dataclass(frozen=True, slots=True)
class NetworkConnectionCommitResult:
    """Occurrence-local result published only after the full root commits."""

    transaction: NetworkTransactionPlan
    lifecycle_mode: NetworkTransportLifecycleMode
    effective_dst_ip: str
    http: HttpContext | None = None
    file_transfers: tuple[FileTransferContext, ...] = ()

    def __post_init__(self) -> None:
        if type(self.transaction) is not NetworkTransactionPlan:
            raise ValueError("Network commit result requires an exact transaction plan")
        if type(self.effective_dst_ip) is not str or not self.effective_dst_ip:
            raise ValueError("Network commit result requires an effective destination IP")
        if self.http is not None and type(self.http) is not HttpContext:
            raise ValueError("Network commit result requires an exact HTTP context")
        object.__setattr__(self, "file_transfers", tuple(self.file_transfers))
        if any(type(transfer) is not FileTransferContext for transfer in self.file_transfers):
            raise ValueError("Network commit result requires exact file-transfer contexts")


_CANONICAL_EVENT_DATACLASSES = frozenset(
    {
        NetworkConnectionCommitResult,
        NetworkTransactionPlan,
        NetworkTrafficLedger,
        DirectionalTrafficLedger,
        HttpContext,
        HttpRequestEntityContext,
        HttpMultipartEntityContext,
        HttpEntityPartContext,
        HttpWireSpanContext,
        FileTransferContext,
    }
)


class NetworkCryptographicMaterialPreparation:
    """Resolver-only TLS view that cannot seal or publish its nested overlay."""

    __slots__ = ("__owner", "__preparation_id")

    def __init__(self, owner: NetworkTransactionRuntime, preparation_id: int) -> None:
        self.__owner = owner
        self.__preparation_id = preparation_id

    def public_key_spki(
        self,
        identity: str,
        *,
        key_type: str,
        key_size: int,
    ) -> bytes:
        """Resolve deterministic SPKI material into the private overlay."""

        return self.__owner._resolve_crypto_public_key(
            self,
            preparation_id=self.__preparation_id,
            identity=identity,
            key_type=key_type,
            key_size=key_size,
        )

    def resolve_authority(
        self,
        *,
        subject_name: str,
        issuer_name: str,
        key_type: str,
        key_size: int,
    ) -> CertificateAuthorityMaterial:
        """Resolve one authority into the private overlay."""

        return self.__owner._resolve_crypto_authority(
            self,
            preparation_id=self.__preparation_id,
            subject_name=subject_name,
            issuer_name=issuer_name,
            key_type=key_type,
            key_size=key_size,
        )

    def resolve_certificate(
        self,
        *,
        backend_identity: str,
        subject_name: str,
        issuer_name: str,
        not_valid_before: int,
        not_valid_after: int,
        key_type: str,
        key_size: int,
        signature_algorithm: str,
        san_dns: tuple[str, ...] = (),
        basic_constraints_ca: bool = False,
        host_certificate: bool = True,
        client_certificate: bool = False,
    ) -> CertificateIdentityPlan:
        """Resolve one certificate into the private overlay."""

        return self.__owner._resolve_crypto_certificate(
            self,
            preparation_id=self.__preparation_id,
            backend_identity=backend_identity,
            subject_name=subject_name,
            issuer_name=issuer_name,
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
            key_type=key_type,
            key_size=key_size,
            signature_algorithm=signature_algorithm,
            san_dns=san_dns,
            basic_constraints_ca=basic_constraints_ca,
            host_certificate=host_certificate,
            client_certificate=client_certificate,
        )


@dataclass(frozen=True, slots=True)
class NetworkTransactionPreparationToken:
    """Opaque owner-authenticated reservation for one finalized network root."""

    preparation_id: int
    transaction_id: str
    action_group_id: str
    materialization_mode: ConnectionMaterializationMode
    lifecycle_mode: NetworkTransportLifecycleMode
    linearization_time: datetime
    overlay_digest: str
    state_publication_token: str
    cryptographic_publication_token: str
    _runtime_token: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")

    @property
    def publication_token(self) -> str:
        """Return the stable keyed proof bound into the outer coordinator."""

        return self._integrity_token


@dataclass(frozen=True, slots=True)
class NetworkTransactionPreparationReceipt:
    """Authenticated proof that one prepared runtime overlay committed once."""

    publication_token: str
    transaction_id: str
    overlay_digest: str
    committed_runtime_digest: str
    cryptographic_receipt: CryptographicMaterialPreparationReceipt
    committed_point_mutations: int
    _runtime_token: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")

    @property
    def receipt_token(self) -> str:
        """Return the keyed proof over the exact committed runtime outcome."""

        return self._integrity_token


@dataclass(frozen=True, slots=True)
class PreparedNetworkTransactionRoot:
    """Frozen State and runtime inputs ready for outer-authority composition."""

    transaction: NetworkTransactionPlan
    state_plan: ConnectionCompositeMaterializationPlan
    runtime_token: NetworkTransactionPreparationToken
    result: NetworkConnectionCommitResult


@dataclass(frozen=True, slots=True)
class NetworkTransactionRuntimeCensus:
    """Constant-time structural census for generator-local network state."""

    live_points: int
    tombstone_points: int
    open_preparations: int
    prepared_transactions: int
    claimed_transactions: int
    reserved_points: int
    preparation_fences: int
    reserved_deadlines: int
    active_deadlines: int
    expiry_backing: int
    watermark: datetime
    pending_watermark: datetime | None
    has_last_result: bool


@dataclass(frozen=True, slots=True)
class NetworkRuntimeWatermarkPage:
    """One bounded expiration/pruning page."""

    processed: int
    has_more: bool
    census: NetworkTransactionRuntimeCensus


@dataclass(frozen=True, slots=True)
class _PointSlot:
    generation: int
    value: object | None
    expires_at: datetime
    tombstone_until: datetime | None
    ordinal: int

    @property
    def is_tombstone(self) -> bool:
        return self.tombstone_until is not None


@dataclass(frozen=True, slots=True)
class _PointExpectation:
    family: NetworkRuntimePointFamily
    key: Hashable
    generation: int
    value_digest: str


@dataclass(frozen=True, slots=True)
class _PointMutation:
    family: NetworkRuntimePointFamily
    key: Hashable
    kind: Literal["set", "delete"]
    value: object | None
    expires_at: datetime


def _canonical_expectation(value: object) -> _PointExpectation:
    """Freeze one exact prepared point expectation without caller callbacks."""

    if type(value) is not _PointExpectation:
        raise StateError("Network runtime preparation contains an invalid point expectation")
    family = _canonical_family(value.family)
    key = _canonical_key(value.key)
    if type(value.generation) is not int or value.generation < 0:
        raise StateError("Network runtime preparation contains an invalid point generation")
    if type(value.value_digest) is not str:
        raise StateError("Network runtime preparation contains an invalid point digest")
    return _PointExpectation(family, key, value.generation, value.value_digest)


def _canonical_mutation(value: object) -> _PointMutation:
    """Freeze one exact prepared mutation before any authority publication."""

    if type(value) is not _PointMutation:
        raise StateError("Network runtime preparation contains an invalid point mutation")
    family = _canonical_family(value.family)
    key = _canonical_key(value.key)
    if type(value.kind) is not str or value.kind not in {"set", "delete"}:
        raise StateError("Network runtime preparation contains an invalid mutation kind")
    expires_at = _canonical_datetime(value.expires_at, field_name="point expiry")
    if value.kind == "delete":
        if value.value is not None or expires_at != _MAX_TIME:
            raise StateError("Network runtime deletion mutation has an invalid payload")
        canonical_value = None
    else:
        canonical_value = _canonical_value(value.value)
    return _PointMutation(family, key, value.kind, canonical_value, expires_at)


@dataclass(frozen=True, slots=True)
class _OpenPreparationCapability:
    preparation_id: int
    preparation_identity: int
    stable_id: str
    action_group_id: str
    linearization_time: datetime
    cursor: ConnectionPlanningCursor
    crypto: CryptographicMaterialPreparation
    crypto_owner: object
    crypto_view_identity: int


@dataclass(frozen=True, slots=True)
class _PreparedCapability:
    token_identity: int
    preparation_id: int
    integrity_token: str
    trusted_token: NetworkTransactionPreparationToken
    trusted_root: PreparedNetworkTransactionRoot
    expectations: tuple[_PointExpectation, ...]
    mutations: tuple[_PointMutation, ...]
    reserved_points: tuple[tuple[NetworkRuntimePointFamily, Hashable], ...]
    crypto_token: CryptographicMaterialPreparationToken
    publication_time: datetime


@dataclass(frozen=True, slots=True)
class _ClaimedCompositeCapability:
    """Runtime-owned nested crypto authority for one public outer claim."""

    prepared_identity: int
    preparation_id: int
    token: NetworkTransactionPreparationToken
    crypto_commit: CryptographicMaterialPreparedCommit


@dataclass(frozen=True, slots=True)
class _NetworkDeferredCompositionHandle:
    """Inert internal deferred-composition shape awaiting an RAII owner."""

    kind: _DeferredCompositionKind
    request_id: str
    action_group_id: str


def _token_integrity(secret: bytes, token: NetworkTransactionPreparationToken) -> str:
    preimage = (
        "network-transaction-preparation-v1",
        token.preparation_id,
        token.transaction_id,
        token.action_group_id,
        token.materialization_mode.value,
        token.lifecycle_mode,
        ensure_utc(token.linearization_time),
        token.overlay_digest,
        token.state_publication_token,
        token.cryptographic_publication_token,
        token._runtime_token,
    )
    return hmac.new(secret, repr(preimage).encode(), hashlib.sha256).hexdigest()


def _validated_token_integrity(
    secret: bytes,
    token: NetworkTransactionPreparationToken,
) -> str:
    """Return token integrity or translate malformed caller fields to StateError."""

    if (
        type(token.preparation_id) is not int
        or type(token.transaction_id) is not str
        or type(token.action_group_id) is not str
        or type(token.materialization_mode) is not ConnectionMaterializationMode
        or type(token.lifecycle_mode) is not str
        or token.lifecycle_mode not in {"network", "deferred_session", "application_child"}
        or type(token.linearization_time) is not datetime
        or token.linearization_time.tzinfo is not UTC
        or type(token.overlay_digest) is not str
        or type(token.state_publication_token) is not str
        or type(token.cryptographic_publication_token) is not str
        or type(token._runtime_token) is not int
        or type(token._integrity_token) is not str
    ):
        raise StateError("Network transaction token contains malformed fields")
    try:
        return _token_integrity(secret, token)
    except (AttributeError, TypeError, ValueError) as exc:
        raise StateError("Network transaction token contains malformed fields") from exc


def _receipt_integrity(secret: bytes, receipt: NetworkTransactionPreparationReceipt) -> str:
    preimage = (
        "network-transaction-preparation-receipt-v1",
        receipt.publication_token,
        receipt.transaction_id,
        receipt.overlay_digest,
        receipt.committed_runtime_digest,
        receipt.cryptographic_receipt.receipt_token,
        receipt.committed_point_mutations,
        receipt._runtime_token,
    )
    return hmac.new(secret, repr(preimage).encode(), hashlib.sha256).hexdigest()


def _validated_receipt_integrity(
    secret: bytes,
    receipt: NetworkTransactionPreparationReceipt,
) -> str:
    """Return receipt integrity or reject malformed caller-owned fields."""

    crypto_receipt = receipt.cryptographic_receipt
    if (
        type(receipt) is not NetworkTransactionPreparationReceipt
        or type(receipt.publication_token) is not str
        or type(receipt.transaction_id) is not str
        or type(receipt.overlay_digest) is not str
        or type(receipt.committed_runtime_digest) is not str
        or type(crypto_receipt) is not CryptographicMaterialPreparationReceipt
        or type(crypto_receipt.preparation_id) is not int
        or crypto_receipt.preparation_id <= 0
        or type(crypto_receipt.publication_token) is not str
        or type(crypto_receipt.overlay_digest) is not str
        or type(crypto_receipt.committed_digest) is not str
        or type(crypto_receipt.public_key_writes) is not int
        or crypto_receipt.public_key_writes < 0
        or type(crypto_receipt.authority_writes) is not int
        or crypto_receipt.authority_writes < 0
        or type(crypto_receipt.certificate_writes) is not int
        or crypto_receipt.certificate_writes < 0
        or type(crypto_receipt._registry_token) is not int
        or type(crypto_receipt._integrity_token) is not str
        or type(receipt.committed_point_mutations) is not int
        or receipt.committed_point_mutations < 0
        or type(receipt._runtime_token) is not int
        or type(receipt._integrity_token) is not str
    ):
        raise StateError("Network transaction receipt contains malformed fields")
    try:
        return _receipt_integrity(secret, receipt)
    except (AttributeError, TypeError, ValueError) as exc:
        raise StateError("Network transaction receipt contains malformed fields") from exc


class NetworkTransactionPreparation:
    """Open copy-on-write planner for one physical transport or app child."""

    __slots__ = (
        "_cancelled",
        "_crypto_view",
        "_expectations",
        "_linearization_time",
        "_mutations",
        "_owner",
        "_preparation_id",
        "_sealed",
        "_stable_id",
    )

    def __init__(
        self,
        owner: NetworkTransactionRuntime,
        *,
        preparation_id: int,
        stable_id: str,
        linearization_time: datetime,
        crypto_view: NetworkCryptographicMaterialPreparation,
    ) -> None:
        self._owner = owner
        self._preparation_id = preparation_id
        self._stable_id = stable_id
        self._linearization_time = linearization_time
        self._crypto_view = crypto_view
        self._expectations: dict[tuple[NetworkRuntimePointFamily, Hashable], _PointExpectation] = {}
        self._mutations: dict[tuple[NetworkRuntimePointFamily, Hashable], _PointMutation] = {}
        self._sealed = False
        self._cancelled = False

    @property
    def rng(self) -> Any:
        """Return the revocable isolated RNG owned by the State cursor."""

        self._require_open()
        return self._owner._preparation_rng(self)

    @property
    def cryptographic_material(self) -> NetworkCryptographicMaterialPreparation:
        """Return the nested TLS-only cryptographic copy-on-write view."""

        self._require_open()
        return self._crypto_view

    @property
    def preparation_id(self) -> int:
        """Return this runtime's monotonic preparation identifier."""

        return self._preparation_id

    def reserve_physical_identity(self) -> ConnectionIdentityPlan:
        """Reserve the single physical connection identity from the isolated RNG."""

        self._require_open()
        return self._owner._reserve_physical_identity(self)

    def read_point(
        self,
        family: NetworkRuntimePointFamily,
        key: Hashable,
        default: object = None,
        *,
        at: datetime | None = None,
    ) -> object:
        """Read one exact point through the overlay and reserve its preimage."""

        self._require_open()
        canonical_family = _canonical_family(family)
        canonical_key = _canonical_key(key)
        canonical_default = _canonical_value(default)
        canonical_at = None if at is None else _canonical_datetime(at, field_name="point read time")
        point_key = (canonical_family, canonical_key)
        mutation = self._mutations.get(point_key)
        if mutation is not None:
            if mutation.kind == "delete":
                return canonical_default
            if canonical_at is not None and mutation.expires_at <= canonical_at:
                return canonical_default
            return _canonical_value(mutation.value)
        expectation, value, expires_at, visible = self._owner._reserve_point(
            self,
            canonical_family,
            canonical_key,
        )
        self._expectations.setdefault(point_key, expectation)
        if not visible or (canonical_at is not None and expires_at <= canonical_at):
            return canonical_default
        return _canonical_value(value)

    def stage_point(
        self,
        family: NetworkRuntimePointFamily,
        key: Hashable,
        value: object,
        *,
        expires_at: datetime | None = None,
    ) -> None:
        """Stage one exact point replacement without changing canonical state."""

        self._require_open()
        canonical_family = _canonical_family(family)
        canonical_key = _canonical_key(key)
        canonical_value = _canonical_value(value)
        canonical_expiry = (
            _MAX_TIME
            if expires_at is None
            else _canonical_datetime(expires_at, field_name="point expiry")
        )
        self._owner._validate_prepared_point_expiry(self, canonical_expiry)
        point_key = (canonical_family, canonical_key)
        if point_key not in self._expectations:
            expectation, _value, _expires_at, _visible = self._owner._reserve_point(
                self,
                canonical_family,
                canonical_key,
            )
            self._expectations[point_key] = expectation
        self._mutations[point_key] = _PointMutation(
            family=canonical_family,
            key=canonical_key,
            kind="set",
            value=canonical_value,
            expires_at=canonical_expiry,
        )

    def delete_point(self, family: NetworkRuntimePointFamily, key: Hashable) -> None:
        """Stage one exact point deletion while retaining an ABA generation."""

        self._require_open()
        canonical_family = _canonical_family(family)
        canonical_key = _canonical_key(key)
        point_key = (canonical_family, canonical_key)
        if point_key not in self._expectations:
            expectation, _value, _expires_at, _visible = self._owner._reserve_point(
                self,
                canonical_family,
                canonical_key,
            )
            self._expectations[point_key] = expectation
        self._mutations[point_key] = _PointMutation(
            family=canonical_family,
            key=canonical_key,
            kind="delete",
            value=None,
            expires_at=_MAX_TIME,
        )

    def seal(
        self,
        *,
        transaction: NetworkTransactionPlan,
        lifecycle_mode: NetworkTransportLifecycleMode,
        materialization_mode: ConnectionMaterializationMode,
        source_system: str = "",
        source_hostname: str = "",
        hostname: str = "",
        initiating_pid: int = -1,
        batch: MaterializationBatchPlan | None = None,
        process_activity: tuple[ProcessActivityPatch, ...] = (),
        session_activity: tuple[SessionActivityPatch, ...] = (),
        result: NetworkConnectionCommitResult | None = None,
    ) -> PreparedNetworkTransactionRoot:
        """Seal exact State, crypto, and point overlays without publishing them."""

        self._require_open()
        try:
            if type(transaction) is not NetworkTransactionPlan:
                raise StateError("Network preparation requires a canonical transaction plan")
            if transaction.stable_id != self._stable_id:
                raise StateError("Network transaction changed its preparation stable identity")
            if lifecycle_mode not in {"network", "deferred_session", "application_child"}:
                raise StateError(f"Unsupported network lifecycle mode {lifecycle_mode!r}")
            if materialization_mode is ConnectionMaterializationMode.PHYSICAL:
                if lifecycle_mode == "application_child" or transaction.application_layer_only:
                    raise StateError("Physical preparation cannot publish an application child")
            elif materialization_mode is ConnectionMaterializationMode.APPLICATION_CHILD:
                if lifecycle_mode != "application_child" or not transaction.application_layer_only:
                    raise StateError(
                        "Application-child preparation requires application_child mode"
                    )
                if self._expectations or self._mutations:
                    raise StateError(
                        "Application-child preparation cannot publish root-local runtime points"
                    )
            else:
                raise StateError("Network transaction requires an explicit materialization mode")
            final_result = result or NetworkConnectionCommitResult(
                transaction=transaction,
                lifecycle_mode=lifecycle_mode,
                effective_dst_ip=transaction.dst_ip,
            )
            if type(final_result) is not NetworkConnectionCommitResult:
                raise StateError("Network preparation requires a typed commit result")
            if (
                final_result.transaction != transaction
                or final_result.lifecycle_mode != lifecycle_mode
            ):
                raise StateError("Network commit result disagrees with the finalized transaction")
            trusted_result = _canonical_commit_result(final_result)
            trusted_transaction = trusted_result.transaction
            state_transaction = copy.deepcopy(trusted_transaction)
            _validate_canonical_event_tree(state_transaction)

            crypto_token = self._owner._seal_open_crypto(self)
            if materialization_mode is ConnectionMaterializationMode.APPLICATION_CHILD and (
                crypto_token.public_key_writes
                or crypto_token.authority_writes
                or crypto_token.certificate_writes
            ):
                raise StateError(
                    "Application-child preparation cannot publish root-local TLS material"
                )
            state_plan = self._owner._finalize_state_plan(
                self,
                state_transaction,
                source_system=source_system,
                source_hostname=source_hostname,
                hostname=hostname,
                initiating_pid=initiating_pid,
                mode=materialization_mode,
                batch=batch,
                process_activity=process_activity,
                session_activity=session_activity,
            )
            root = self._owner._seal_preparation(
                self,
                transaction=trusted_transaction,
                state_plan=state_plan,
                lifecycle_mode=lifecycle_mode,
                materialization_mode=materialization_mode,
                result=trusted_result,
                crypto_token=crypto_token,
            )
        except BaseException:
            self._abort_failed_seal()
            raise
        self._sealed = True
        return root

    def cancel(self) -> None:
        """Cancel this open preparation without changing State, RNG, or caches."""

        self._require_open()
        try:
            self._owner._cancel_open_crypto(self)
        finally:
            try:
                self._owner._cancel_open_cursor(self)
            finally:
                self._owner._cancel_open_preparation(self)
                self._cancelled = True

    def _abort_failed_seal(self) -> None:
        """Revoke every still-open nested capability without masking the seal error."""

        try:
            self._owner._cancel_open_crypto(self)
        except StateError:
            pass
        try:
            self._owner._cancel_open_cursor(self)
        except StateError:
            # State sealing is allocation-free and retains no cursor capability.
            pass
        try:
            self._owner._cancel_open_preparation(self)
        except StateError:
            pass
        self._cancelled = True

    def _require_open(self) -> None:
        if self._cancelled:
            raise StateError("Network transaction preparation is cancelled")
        if self._sealed:
            raise StateError("Network transaction preparation is already sealed")


class NetworkTransactionPreparedCommit:
    """No-lock claim capability for one structurally no-fail runtime commit."""

    __slots__ = ("_active", "_committed", "_owner", "_receipt")

    def __init__(
        self,
        owner: NetworkTransactionRuntime,
    ) -> None:
        self._owner = owner
        self._active = True
        self._committed = False
        self._receipt: NetworkTransactionPreparationReceipt | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact claim committed once."""

        return self._committed

    @property
    def receipt(self) -> NetworkTransactionPreparationReceipt | None:
        """Return the signed receipt after commit."""

        return self._receipt

    def commit_no_fail(self) -> NetworkTransactionPreparationReceipt:
        """Commit nested crypto then the prevalidated primitive runtime writes."""

        if not self._active:
            raise StateError("Network runtime prepared commit is no longer active")
        if self._committed:
            raise StateError("Network runtime preparation was already committed")
        receipt = self._owner._commit_outer_claim_no_fail(self)
        self._receipt = receipt
        self._committed = True
        return receipt

    def _close(self) -> None:
        self._active = False


class NetworkTransactionRuntime:
    """Versioned exact-point authority for generator-local network planning."""

    def __init__(
        self,
        *,
        state_manager: StateManager,
        cryptographic_material: CryptographicMaterialRegistry,
        window_start: datetime,
        window_end: datetime,
        tombstone_retention: timedelta = timedelta(days=1),
    ) -> None:
        canonical_start = _canonical_datetime(window_start, field_name="window_start")
        canonical_end = _canonical_datetime(window_end, field_name="window_end")
        if canonical_end <= canonical_start:
            raise ValueError("Network runtime window_end must follow window_start")
        if type(tombstone_retention) is not timedelta or tombstone_retention <= timedelta(0):
            raise ValueError("Network runtime tombstone retention must be positive")
        try:
            _MAX_TIME - tombstone_retention
        except OverflowError as exc:
            raise ValueError(
                "Network runtime tombstone retention exceeds the representable datetime range"
            ) from exc
        if tombstone_retention > _MAX_TIME - _MIN_TIME:
            raise ValueError(
                "Network runtime tombstone retention exceeds the representable datetime range"
            )
        self.state_manager = state_manager
        self.cryptographic_material = cryptographic_material
        self._window_start = canonical_start
        self._window_end = canonical_end
        self._tombstone_retention = tombstone_retention
        self._watermark = canonical_start
        self._pending_watermark: datetime | None = None
        self._lock = RLock()
        self._secret = secrets.token_bytes(32)
        self._next_preparation_id = 1
        self._next_point_ordinal = 1
        self._points: dict[_PointKey, _PointSlot] = {}
        self._expiry_heap = _IndexedExpiryHeap()
        self._preparation_fences = _IndexedPreparationFenceHeap()
        self._reserved_deadlines = _IndexedExpiryHeap()
        self._live_points = 0
        self._tombstone_points = 0
        self._open_preparations: dict[int, _OpenPreparationCapability] = {}
        self._open_objects: dict[int, NetworkTransactionPreparation] = {}
        self._open_capabilities_by_identity: dict[int, _OpenPreparationCapability] = {}
        self._prepared_tokens: dict[int, NetworkTransactionPreparationToken] = {}
        self._prepared_capabilities: dict[int, _PreparedCapability] = {}
        self._claimed_preparations: set[int] = set()
        self._claimed_composites: dict[int, _ClaimedCompositeCapability] = {}
        self._reserved_points: dict[tuple[NetworkRuntimePointFamily, Hashable], int] = {}
        self._reserved_by_preparation: dict[
            int, set[tuple[NetworkRuntimePointFamily, Hashable]]
        ] = {}
        self._last_result: NetworkConnectionCommitResult | None = None
        self._point_state_xor = 0

    @property
    def window_start(self) -> datetime:
        """Return the inclusive runtime window start."""

        return self._window_start

    @property
    def window_end(self) -> datetime:
        """Return the exclusive planning fence used by this generator run."""

        return self._window_end

    @property
    def watermark(self) -> datetime:
        """Return the last fully drained canonical runtime watermark."""

        with self._lock:
            return self._watermark

    @property
    def last_result(self) -> NetworkConnectionCommitResult | None:
        """Return the committed compatibility snapshot, never prepared state."""

        with self._lock:
            return copy.deepcopy(self._last_result)

    def begin(
        self,
        *,
        owner_rng: random.Random,
        stable_id: str,
        linearization_time: datetime,
        action_group_id: str = "",
    ) -> NetworkTransactionPreparation:
        """Begin one allocation-free point/State/crypto preparation."""

        if not stable_id.strip():
            raise ValueError("Network transaction stable_id must not be empty")
        canonical_time = _canonical_datetime(
            linearization_time,
            field_name="linearization_time",
        )
        cursor = self.state_manager.begin_connection_planning(owner_rng)
        crypto_owner = object()
        try:
            crypto = self.cryptographic_material.begin_tls_preparation(owner=crypto_owner)
        except BaseException:
            cursor.cancel()
            raise
        try:
            with self._lock:
                fence = self._pending_watermark or self._watermark
                if canonical_time < fence:
                    raise StateError("Network transaction preparation starts behind the watermark")
                if canonical_time >= self._window_end:
                    raise StateError(
                        "Network transaction preparation starts at or after the runtime window end"
                    )
                preparation_id = self._next_preparation_id
                self._next_preparation_id += 1
                crypto_view = NetworkCryptographicMaterialPreparation(self, preparation_id)
                preparation = NetworkTransactionPreparation(
                    self,
                    preparation_id=preparation_id,
                    stable_id=stable_id,
                    linearization_time=canonical_time,
                    crypto_view=crypto_view,
                )
                capability = _OpenPreparationCapability(
                    preparation_id=preparation_id,
                    preparation_identity=id(preparation),
                    stable_id=stable_id,
                    action_group_id=action_group_id,
                    linearization_time=canonical_time,
                    cursor=cursor,
                    crypto=crypto,
                    crypto_owner=crypto_owner,
                    crypto_view_identity=id(crypto_view),
                )
                self._open_preparations[preparation_id] = capability
                self._open_objects[id(preparation)] = preparation
                self._open_capabilities_by_identity[id(preparation)] = capability
                self._preparation_fences.set(preparation_id, canonical_time)
                return preparation
        except BaseException:
            cursor.cancel()
            crypto.cancel(owner=crypto_owner)
            raise

    def get_point(
        self,
        family: NetworkRuntimePointFamily,
        key: Hashable,
        default: object = None,
        *,
        at: datetime | None = None,
    ) -> object:
        """Return one canonical point without exposing retained mutable values."""

        canonical_family = _canonical_family(family)
        canonical_key = _canonical_key(key)
        canonical_default = _canonical_value(default)
        canonical_at = None if at is None else _canonical_datetime(at, field_name="point read time")
        with self._lock:
            slot = self._points.get((canonical_family, canonical_key))
            if slot is None or slot.is_tombstone:
                return canonical_default
            if canonical_at is not None and slot.expires_at <= canonical_at:
                return canonical_default
            return _canonical_value(slot.value)

    def set_point(
        self,
        family: NetworkRuntimePointFamily,
        key: Hashable,
        value: object,
        *,
        expires_at: datetime | None = None,
    ) -> None:
        """Compatibility mutation fenced against any exact prepared reader/writer."""

        canonical_family = _canonical_family(family)
        canonical_key = _canonical_key(key)
        canonical_value = _canonical_value(value)
        canonical_expiry = (
            _MAX_TIME
            if expires_at is None
            else _canonical_datetime(expires_at, field_name="point expiry")
        )
        with self._lock:
            if canonical_expiry != _MAX_TIME and canonical_expiry > self._window_end:
                raise StateError("Network runtime point expiry exceeds the runtime window")
            if canonical_expiry <= (self._pending_watermark or self._watermark):
                raise StateError("Network runtime point expiry must follow the watermark")
            self._reject_reserved_point_locked((canonical_family, canonical_key))
            mutation = _PointMutation(
                canonical_family,
                canonical_key,
                "set",
                canonical_value,
                canonical_expiry,
            )
            self._apply_point_mutation_locked(mutation, trusted_value=True)

    def delete_point(self, family: NetworkRuntimePointFamily, key: Hashable) -> bool:
        """Compatibility deletion that retains an ABA-safe bounded tombstone."""

        canonical_family = _canonical_family(family)
        canonical_key = _canonical_key(key)
        with self._lock:
            point_key = (canonical_family, canonical_key)
            self._reject_reserved_point_locked(point_key)
            slot = self._points.get(point_key)
            if slot is None or slot.is_tombstone:
                return False
            self._apply_point_mutation_locked(
                _PointMutation(canonical_family, canonical_key, "delete", None, _MAX_TIME)
            )
            return True

    def cancel_preparation(self, token: NetworkTransactionPreparationToken) -> bool:
        """Cancel one unclaimed sealed preparation and release exact reservations."""

        if type(token) is not NetworkTransactionPreparationToken:
            return False
        crypto_token: CryptographicMaterialPreparationToken | None = None
        error: StateError | None = None
        with self._lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                return False
            if capability.preparation_id in self._claimed_preparations:
                return False
            try:
                capability = self._active_capability_locked(token)
            except StateError as exc:
                crypto_token = capability.crypto_token
                self._release_capability_locked(capability)
                error = exc
            else:
                if capability.preparation_id in self._claimed_preparations:
                    return False
                crypto_token = capability.crypto_token
                self._release_capability_locked(capability)
        assert crypto_token is not None
        self.cryptographic_material.cancel_tls_preparation(crypto_token)
        if error is not None:
            raise error
        return True

    def authenticates_preparation_token(
        self,
        token: NetworkTransactionPreparationToken,
        *,
        expected_transaction_id: str | None = None,
    ) -> bool:
        """Return whether this runtime owns one intact active token."""

        if type(token) is not NetworkTransactionPreparationToken:
            return False
        with self._lock:
            try:
                capability = self._active_capability_locked(token)
            except StateError:
                return False
            if (
                expected_transaction_id is not None
                and capability.trusted_token.transaction_id != expected_transaction_id
            ):
                return False
            crypto_token = capability.crypto_token
            root = capability.trusted_root
        return self.cryptographic_material.authenticates_tls_preparation_token(
            crypto_token
        ) and self.state_manager.authenticates_materialization_plan(root.state_plan)

    def authenticates_preparation_root(self, root: object) -> bool:
        """Authenticate one exact active root against its runtime-owned snapshot.

        The root is a frozen value carrier rather than a second identity
        capability. An exact semantic replacement may therefore authenticate,
        but it must retain the original one-shot runtime token. Caller-visible
        transaction and result values are compared with the private trusted copy
        retained at seal time before an outer coordinator may consume them.
        """

        if type(root) is not PreparedNetworkTransactionRoot:
            return False
        token = root.runtime_token
        state_plan = root.state_plan
        transaction = root.transaction
        result = root.result
        if (
            type(token) is not NetworkTransactionPreparationToken
            or type(state_plan) is not ConnectionCompositeMaterializationPlan
            or type(transaction) is not NetworkTransactionPlan
            or type(result) is not NetworkConnectionCommitResult
        ):
            return False

        with self._lock:
            try:
                capability = self._active_capability_locked(token)
            except (AttributeError, StateError, TypeError, ValueError):
                return False
            trusted_root = capability.trusted_root
            crypto_token = capability.crypto_token

        try:
            transaction_digest = _value_digest(transaction)
            result_digest = _value_digest(result)
            state_transaction_digest = _value_digest(state_plan.transaction)
            result_transaction_digest = _value_digest(result.transaction)
            trusted_transaction_digest = _value_digest(trusted_root.transaction)
            trusted_result_digest = _value_digest(trusted_root.result)
            trusted_state_transaction_digest = _value_digest(trusted_root.state_plan.transaction)
            state_publication_token = state_plan.publication_token
            trusted_state_publication_token = trusted_root.state_plan.publication_token
            state_mode = state_plan.mode
            trusted_state_mode = trusted_root.state_plan.mode
            crypto_publication_token = crypto_token.publication_token
        except (
            AttributeError,
            LookupError,
            RecursionError,
            RuntimeError,
            StateError,
            TypeError,
            ValueError,
        ):
            return False

        if (
            type(state_publication_token) is not str
            or not state_publication_token
            or type(state_mode) is not ConnectionMaterializationMode
            or token.transaction_id != transaction.stable_id
            or token.state_publication_token != state_publication_token
            or token.cryptographic_publication_token != crypto_publication_token
            or token.materialization_mode is not state_mode
            or token.lifecycle_mode != result.lifecycle_mode
            or transaction_digest != state_transaction_digest
            or transaction_digest != result_transaction_digest
            or transaction_digest != trusted_transaction_digest
            or transaction_digest != trusted_state_transaction_digest
            or result_digest != trusted_result_digest
            or state_publication_token != trusted_state_publication_token
            or state_mode is not trusted_state_mode
            or token.publication_token != trusted_root.runtime_token.publication_token
        ):
            return False
        if state_mode is ConnectionMaterializationMode.PHYSICAL:
            if token.lifecycle_mode == "application_child" or transaction.application_layer_only:
                return False
        elif state_mode is ConnectionMaterializationMode.APPLICATION_CHILD:
            if (
                token.lifecycle_mode != "application_child"
                or not transaction.application_layer_only
            ):
                return False
        else:
            return False

        try:
            state_authentic = self.state_manager.authenticates_materialization_plan(state_plan)
            crypto_authentic = self.cryptographic_material.authenticates_tls_preparation_token(
                crypto_token
            )
        except (
            AttributeError,
            LookupError,
            RecursionError,
            RuntimeError,
            StateError,
            TypeError,
            ValueError,
        ):
            return False
        return state_authentic and crypto_authentic

    def authenticates_preparation_receipt(
        self,
        receipt: NetworkTransactionPreparationReceipt,
        *,
        token: NetworkTransactionPreparationToken | None = None,
    ) -> bool:
        """Authenticate one exact runtime receipt and optional issuing token."""

        if type(receipt) is not NetworkTransactionPreparationReceipt:
            return False
        if receipt._runtime_token != id(self):
            return False
        if type(receipt.cryptographic_receipt) is not CryptographicMaterialPreparationReceipt:
            return False
        try:
            expected = _validated_receipt_integrity(self._secret, receipt)
        except StateError:
            return False
        if not hmac.compare_digest(receipt._integrity_token, expected):
            return False
        if token is not None:
            if type(token) is not NetworkTransactionPreparationToken:
                return False
            if token._runtime_token != id(self):
                return False
            try:
                expected_token = _validated_token_integrity(self._secret, token)
            except StateError:
                return False
            if not hmac.compare_digest(token.publication_token, expected_token):
                return False
            if receipt.publication_token != token.publication_token:
                return False
            if receipt.transaction_id != token.transaction_id:
                return False
            if receipt.overlay_digest != token.overlay_digest:
                return False
        return self.cryptographic_material.authenticates_tls_preparation_receipt(
            receipt.cryptographic_receipt
        )

    @contextmanager
    def claimed_preparation(
        self,
        token: NetworkTransactionPreparationToken,
    ) -> Iterator[NetworkTransactionPreparedCommit]:
        """Claim a runtime and nested crypto token without retaining either lock."""

        capability = self._claim_preparation(token)
        try:
            with self.cryptographic_material.prepared_tls_material(
                capability.crypto_token
            ) as crypto_commit:
                prepared = NetworkTransactionPreparedCommit(self)
                self._register_claimed_composite(
                    prepared,
                    capability=capability,
                    token=token,
                    crypto_commit=crypto_commit,
                )
                try:
                    yield prepared
                finally:
                    if not prepared.committed:
                        self._cancel_claimed(token)
                    self._close_claimed_composite(prepared)
                    prepared._close()
        except BaseException:
            self._cancel_claimed(token)
            raise

    def advance_watermark_page(
        self,
        cutoff: datetime,
        *,
        limit: int = 4096,
    ) -> NetworkRuntimeWatermarkPage:
        """Expire/prune one bounded deterministic page without crossing preparations."""

        if limit <= 0:
            raise ValueError("Network runtime watermark page limit must be positive")
        canonical_cutoff = _canonical_datetime(cutoff, field_name="watermark cutoff")
        with self._lock:
            if canonical_cutoff < self._watermark:
                raise StateError("Network runtime watermark cannot move backward")
            if canonical_cutoff > self._window_end:
                canonical_cutoff = self._window_end
            if self._pending_watermark is not None and canonical_cutoff != self._pending_watermark:
                raise StateError("Network runtime watermark page must finish one cutoff")
            if (
                self._preparation_fences
                and canonical_cutoff >= self._preparation_fences.first_deadline()
            ):
                raise StateError("Network runtime watermark is fenced by a preparation")
            if self._reserved_deadlines and self._reserved_deadlines.first()[0] <= canonical_cutoff:
                raise StateError("Network runtime watermark is fenced by a reserved point")
            self._pending_watermark = canonical_cutoff
            work = 0
            processed = 0
            while (
                self._expiry_heap
                and self._expiry_heap.first()[0] <= canonical_cutoff
                and work < limit
            ):
                entry = self._expiry_heap.pop_first()
                deadline, _ordinal, family, key, generation, kind = entry
                work += 1
                point_key = (family, key)
                slot = self._points.get(point_key)
                if slot is None or slot.generation != generation:
                    raise StateError("Network runtime deadline generation diverged")
                if kind == "live":
                    if slot.is_tombstone or slot.expires_at != deadline:
                        raise StateError("Network runtime live deadline diverged")
                    self._apply_point_mutation_locked(
                        _PointMutation(family, key, "delete", None, _MAX_TIME),
                        tombstone_anchor=canonical_cutoff,
                    )
                    processed += 1
                else:
                    if not slot.is_tombstone or slot.tombstone_until != deadline:
                        raise StateError("Network runtime tombstone deadline diverged")
                    self._point_state_xor ^= self._point_slot_state_component(
                        point_key,
                        slot,
                    )
                    self._points.pop(point_key)
                    self._tombstone_points -= 1
                    processed += 1
            has_more = bool(self._expiry_heap and self._expiry_heap.first()[0] <= canonical_cutoff)
            if not has_more:
                self._watermark = canonical_cutoff
                self._pending_watermark = None
            return NetworkRuntimeWatermarkPage(
                processed=processed,
                has_more=has_more,
                census=self._census_locked(),
            )

    def census(self) -> NetworkTransactionRuntimeCensus:
        """Return constant-time structural runtime metrics."""

        with self._lock:
            return self._census_locked()

    def state_digest(self) -> str:
        """Return the constant-time committed-state audit digest."""

        with self._lock:
            return self._state_digest_locked()

    def _census_locked(self) -> NetworkTransactionRuntimeCensus:
        return NetworkTransactionRuntimeCensus(
            live_points=self._live_points,
            tombstone_points=self._tombstone_points,
            open_preparations=len(self._open_preparations),
            prepared_transactions=len(self._prepared_tokens),
            claimed_transactions=len(self._claimed_preparations),
            reserved_points=len(self._reserved_points),
            preparation_fences=len(self._preparation_fences),
            reserved_deadlines=len(self._reserved_deadlines),
            active_deadlines=len(self._expiry_heap),
            expiry_backing=len(self._expiry_heap),
            watermark=self._watermark,
            pending_watermark=self._pending_watermark,
            has_last_result=self._last_result is not None,
        )

    def _preparation_rng(self, preparation: NetworkTransactionPreparation) -> Any:
        """Return the State-owned isolated RNG without exposing its cursor."""

        with self._lock:
            cursor = self._active_open_preparation_locked(preparation).cursor
        return cursor.rng

    def _reserve_physical_identity(
        self,
        preparation: NetworkTransactionPreparation,
    ) -> ConnectionIdentityPlan:
        """Reserve one physical identity through the runtime-owned State cursor."""

        with self._lock:
            cursor = self._active_open_preparation_locked(preparation).cursor
        return cursor.reserve_identity()

    def _active_crypto_view_locked(
        self,
        view: NetworkCryptographicMaterialPreparation,
        *,
        preparation_id: int,
    ) -> CryptographicMaterialPreparation:
        capability = self._open_preparations.get(preparation_id)
        if capability is None or capability.crypto_view_identity != id(view):
            raise StateError("Network TLS preparation view is stale or foreign")
        return capability.crypto

    def _resolve_crypto_public_key(
        self,
        view: NetworkCryptographicMaterialPreparation,
        *,
        preparation_id: int,
        identity: str,
        key_type: str,
        key_size: int,
    ) -> bytes:
        with self._lock:
            crypto = self._active_crypto_view_locked(
                view,
                preparation_id=preparation_id,
            )
        return crypto.public_key_spki(identity, key_type=key_type, key_size=key_size)

    def _resolve_crypto_authority(
        self,
        view: NetworkCryptographicMaterialPreparation,
        *,
        preparation_id: int,
        subject_name: str,
        issuer_name: str,
        key_type: str,
        key_size: int,
    ) -> CertificateAuthorityMaterial:
        with self._lock:
            crypto = self._active_crypto_view_locked(
                view,
                preparation_id=preparation_id,
            )
        return crypto.resolve_authority(
            subject_name=subject_name,
            issuer_name=issuer_name,
            key_type=key_type,
            key_size=key_size,
        )

    def _resolve_crypto_certificate(
        self,
        view: NetworkCryptographicMaterialPreparation,
        *,
        preparation_id: int,
        backend_identity: str,
        subject_name: str,
        issuer_name: str,
        not_valid_before: int,
        not_valid_after: int,
        key_type: str,
        key_size: int,
        signature_algorithm: str,
        san_dns: tuple[str, ...],
        basic_constraints_ca: bool,
        host_certificate: bool,
        client_certificate: bool,
    ) -> CertificateIdentityPlan:
        with self._lock:
            crypto = self._active_crypto_view_locked(
                view,
                preparation_id=preparation_id,
            )
        return crypto.resolve_certificate(
            backend_identity=backend_identity,
            subject_name=subject_name,
            issuer_name=issuer_name,
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
            key_type=key_type,
            key_size=key_size,
            signature_algorithm=signature_algorithm,
            san_dns=san_dns,
            basic_constraints_ca=basic_constraints_ca,
            host_certificate=host_certificate,
            client_certificate=client_certificate,
        )

    def _seal_open_crypto(
        self,
        preparation: NetworkTransactionPreparation,
    ) -> CryptographicMaterialPreparationToken:
        with self._lock:
            capability = self._active_open_preparation_locked(preparation)
            crypto = capability.crypto
            crypto_owner = capability.crypto_owner
        return crypto.seal(owner=crypto_owner)

    def _cancel_open_crypto(self, preparation: NetworkTransactionPreparation) -> None:
        with self._lock:
            capability = self._active_open_preparation_locked(preparation)
            crypto = capability.crypto
            crypto_owner = capability.crypto_owner
        crypto.cancel(owner=crypto_owner)

    def _cancel_open_cursor(self, preparation: NetworkTransactionPreparation) -> None:
        with self._lock:
            cursor = self._active_open_preparation_locked(preparation).cursor
        cursor.cancel()

    def _finalize_state_plan(
        self,
        preparation: NetworkTransactionPreparation,
        transaction: NetworkTransactionPlan,
        *,
        source_system: str,
        source_hostname: str,
        hostname: str,
        initiating_pid: int,
        mode: ConnectionMaterializationMode,
        batch: MaterializationBatchPlan | None,
        process_activity: tuple[ProcessActivityPatch, ...],
        session_activity: tuple[SessionActivityPatch, ...],
    ) -> ConnectionCompositeMaterializationPlan:
        with self._lock:
            cursor = self._active_open_preparation_locked(preparation).cursor
        return self.state_manager.finalize_connection_composite_materialization(
            cursor,
            transaction,
            source_system=source_system,
            source_hostname=source_hostname,
            hostname=hostname,
            initiating_pid=initiating_pid,
            mode=mode,
            batch=batch,
            process_activity=process_activity,
            session_activity=session_activity,
        )

    def _reserve_point(
        self,
        preparation: NetworkTransactionPreparation,
        family: NetworkRuntimePointFamily,
        key: Hashable,
    ) -> tuple[_PointExpectation, object | None, datetime, bool]:
        point_key = (family, key)
        with self._lock:
            capability = self._active_open_preparation_locked(preparation)
            owner = self._reserved_points.get(point_key)
            if owner is not None and owner != capability.preparation_id:
                raise StateError("Network runtime point is reserved by another preparation")
            self._reserved_points[point_key] = capability.preparation_id
            self._reserved_by_preparation.setdefault(capability.preparation_id, set()).add(
                point_key
            )
            slot = self._points.get(point_key)
            if slot is None:
                self._reserved_deadlines.replace(point_key, None)
                expectation = _PointExpectation(family, key, 0, _MISSING_DIGEST)
                return expectation, None, _MAX_TIME, False
            self._reserved_deadlines.replace(
                point_key,
                self._expiry_entry_for_slot(point_key, slot),
            )
            value_digest = _MISSING_DIGEST if slot.is_tombstone else _value_digest(slot.value)
            expectation = _PointExpectation(family, key, slot.generation, value_digest)
            return (
                expectation,
                _canonical_value(slot.value),
                slot.expires_at,
                not slot.is_tombstone,
            )

    def _validate_prepared_point_expiry(
        self,
        preparation: NetworkTransactionPreparation,
        expires_at: datetime,
    ) -> None:
        """Validate one staged deadline against the effective watermark fence."""

        with self._lock:
            capability = self._active_open_preparation_locked(preparation)
            deadline_floor = max(
                self._pending_watermark or self._watermark,
                capability.linearization_time,
            )
            if expires_at <= deadline_floor:
                raise StateError(
                    "Network runtime point expiry must follow the preparation linearization"
                )
            if expires_at != _MAX_TIME and expires_at > self._window_end:
                raise StateError("Network runtime point expiry exceeds the runtime window")

    def _seal_preparation(
        self,
        preparation: NetworkTransactionPreparation,
        *,
        transaction: NetworkTransactionPlan,
        state_plan: ConnectionCompositeMaterializationPlan,
        lifecycle_mode: NetworkTransportLifecycleMode,
        materialization_mode: ConnectionMaterializationMode,
        result: NetworkConnectionCommitResult,
        crypto_token: CryptographicMaterialPreparationToken,
    ) -> PreparedNetworkTransactionRoot:
        canonical_expectations: dict[_PointKey, _PointExpectation] = {}
        for public_key, value in preparation._expectations.items():
            expectation = _canonical_expectation(value)
            canonical_key = _canonical_point_key(public_key)
            if canonical_key != (expectation.family, expectation.key):
                raise StateError("Network runtime expectation key disagrees with its payload")
            if canonical_key in canonical_expectations:
                raise StateError("Network runtime preparation contains duplicate expectations")
            canonical_expectations[canonical_key] = expectation
        expectations = tuple(
            canonical_expectations[key]
            for key in sorted(canonical_expectations, key=_point_key_order)
        )
        canonical_mutations: dict[_PointKey, _PointMutation] = {}
        for public_key, value in preparation._mutations.items():
            mutation = _canonical_mutation(value)
            canonical_key = _canonical_point_key(public_key)
            if canonical_key != (mutation.family, mutation.key):
                raise StateError("Network runtime mutation key disagrees with its payload")
            if canonical_key in canonical_mutations:
                raise StateError("Network runtime preparation contains duplicate mutations")
            canonical_mutations[canonical_key] = mutation
        mutations = tuple(
            canonical_mutations[key] for key in sorted(canonical_mutations, key=_point_key_order)
        )
        trusted_result = result
        overlay_preimage = (
            tuple(
                (
                    item.family.value,
                    _freeze_digest_value(item.key),
                    item.generation,
                    item.value_digest,
                )
                for item in expectations
            ),
            tuple(
                (
                    item.family.value,
                    _freeze_digest_value(item.key),
                    item.kind,
                    _freeze_digest_value(item.value),
                    item.expires_at,
                )
                for item in mutations
            ),
            _freeze_digest_value(trusted_result),
            (
                crypto_token.overlay_digest,
                crypto_token.public_key_writes,
                crypto_token.authority_writes,
                crypto_token.certificate_writes,
            ),
        )
        overlay_digest = hashlib.sha256(repr(overlay_preimage).encode()).hexdigest()
        with self._lock:
            open_capability = self._active_open_preparation_locked(preparation)
        if transaction.stable_id != open_capability.stable_id:
            raise StateError("Network transaction changed its trusted preparation identity")
        transaction_start = _canonical_datetime(
            transaction.started_at,
            field_name="transaction start",
        )
        if transaction_start < self._window_start or transaction_start >= self._window_end:
            raise StateError("Final network transaction starts outside the runtime window")
        if (
            transaction.closed_at is not None
            and _canonical_datetime(
                transaction.closed_at,
                field_name="transaction close",
            )
            > self._window_end
        ):
            raise StateError("Final network transaction closes after the runtime window")
        linearization_time = min(open_capability.linearization_time, transaction_start)
        token = NetworkTransactionPreparationToken(
            preparation_id=open_capability.preparation_id,
            transaction_id=transaction.stable_id,
            action_group_id=open_capability.action_group_id,
            materialization_mode=materialization_mode,
            lifecycle_mode=lifecycle_mode,
            linearization_time=linearization_time,
            overlay_digest=overlay_digest,
            state_publication_token=state_plan.publication_token,
            cryptographic_publication_token=crypto_token.publication_token,
            _runtime_token=id(self),
        )
        token = replace(token, _integrity_token=_token_integrity(self._secret, token))
        public_result = copy.deepcopy(trusted_result)
        root = PreparedNetworkTransactionRoot(
            public_result.transaction,
            state_plan,
            token,
            public_result,
        )
        with self._lock:
            open_capability = self._active_open_preparation_locked(preparation)
            fence = self._pending_watermark or self._watermark
            if linearization_time < fence:
                raise StateError("Final network transaction starts behind the runtime watermark")
            deadline_floor = max(
                fence,
                open_capability.linearization_time,
                transaction_start,
            )
            if any(mutation.expires_at <= deadline_floor for mutation in mutations):
                raise StateError(
                    "Network runtime point expiry was overtaken before preparation seal"
                )
            self._validate_expectations_locked(expectations)
            reserved_points = tuple(
                (expectation.family, expectation.key) for expectation in expectations
            )
            trusted_token = replace(token)
            trusted_root = PreparedNetworkTransactionRoot(
                transaction=trusted_result.transaction,
                state_plan=state_plan,
                runtime_token=trusted_token,
                result=trusted_result,
            )
            capability = _PreparedCapability(
                token_identity=id(token),
                preparation_id=open_capability.preparation_id,
                integrity_token=token.publication_token,
                trusted_token=trusted_token,
                trusted_root=trusted_root,
                expectations=expectations,
                mutations=mutations,
                reserved_points=reserved_points,
                crypto_token=crypto_token,
                publication_time=transaction_start,
            )
            self._open_preparations.pop(open_capability.preparation_id)
            self._open_objects.pop(id(preparation))
            self._open_capabilities_by_identity.pop(id(preparation))
            self._prepared_tokens[open_capability.preparation_id] = token
            self._prepared_capabilities[id(token)] = capability
            self._preparation_fences.set(
                open_capability.preparation_id,
                linearization_time,
            )
            return root

    def _cancel_open_preparation(
        self,
        preparation: NetworkTransactionPreparation,
    ) -> None:
        with self._lock:
            capability = self._active_open_preparation_locked(preparation)
            self._open_preparations.pop(capability.preparation_id)
            self._open_objects.pop(id(preparation))
            self._open_capabilities_by_identity.pop(id(preparation))
            self._preparation_fences.remove(capability.preparation_id)
            self._release_point_reservations_locked(capability.preparation_id)

    def _active_open_preparation_locked(
        self,
        preparation: NetworkTransactionPreparation,
    ) -> _OpenPreparationCapability:
        capability = self._open_capabilities_by_identity.get(id(preparation))
        if (
            capability is None
            or capability.preparation_identity != id(preparation)
            or self._open_preparations.get(capability.preparation_id) is not capability
            or self._open_objects.get(id(preparation)) is not preparation
        ):
            raise StateError("Network transaction preparation is stale or foreign")
        return capability

    def _active_capability_locked(
        self,
        token: NetworkTransactionPreparationToken,
    ) -> _PreparedCapability:
        if type(token) is not NetworkTransactionPreparationToken:
            raise StateError("Network transaction token has an invalid type")
        capability = self._prepared_capabilities.get(id(token))
        if capability is None:
            if token._runtime_token != id(self):
                raise StateError("Network transaction token belongs to another runtime")
            raise StateError("Network transaction token is stale or already consumed")
        active = self._prepared_tokens.get(capability.preparation_id)
        if active is not token:
            raise StateError("Network transaction token is stale or already consumed")
        expected = _validated_token_integrity(self._secret, token)
        if not hmac.compare_digest(token.publication_token, capability.integrity_token) or not (
            hmac.compare_digest(expected, capability.integrity_token)
        ):
            raise StateError("Network transaction token integrity validation failed")
        return capability

    def _claim_preparation(
        self,
        token: NetworkTransactionPreparationToken,
    ) -> _PreparedCapability:
        if type(token) is not NetworkTransactionPreparationToken:
            raise StateError("Network transaction token has an invalid type")
        crypto_to_cancel: CryptographicMaterialPreparationToken | None = None
        error: StateError | None = None
        with self._lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is not None and capability.preparation_id in self._claimed_preparations:
                raise StateError("Network transaction token is already claimed")
            try:
                capability = self._active_capability_locked(token)
                fence = self._pending_watermark or self._watermark
                if capability.trusted_token.linearization_time < fence:
                    raise StateError("Network transaction token starts behind the watermark")
                publication_floor = max(
                    fence,
                    capability.publication_time,
                )
                if any(
                    mutation.expires_at <= publication_floor for mutation in capability.mutations
                ):
                    raise StateError(
                        "Network runtime point expiry was overtaken before preparation claim"
                    )
                self._validate_expectations_locked(capability.expectations)
                self._claimed_preparations.add(capability.preparation_id)
            except StateError as exc:
                if capability is not None:
                    crypto_to_cancel = capability.crypto_token
                    self._release_capability_locked(capability)
                error = exc
        if crypto_to_cancel is not None:
            self.cryptographic_material.cancel_tls_preparation(crypto_to_cancel)
        if error is not None:
            raise error
        assert capability is not None
        return capability

    def _register_claimed_composite(
        self,
        prepared: NetworkTransactionPreparedCommit,
        *,
        capability: _PreparedCapability,
        token: NetworkTransactionPreparationToken,
        crypto_commit: CryptographicMaterialPreparedCommit,
    ) -> None:
        """Retain nested commit authority outside the caller-owned façade."""

        with self._lock:
            if capability.preparation_id not in self._claimed_preparations:
                raise StateError("Network transaction token is not claimed")
            if self._prepared_capabilities.get(id(token)) is not capability:
                raise StateError("Network transaction claim capability changed")
            self._claimed_composites[id(prepared)] = _ClaimedCompositeCapability(
                prepared_identity=id(prepared),
                preparation_id=capability.preparation_id,
                token=token,
                crypto_commit=crypto_commit,
            )

    def _close_claimed_composite(
        self,
        prepared: NetworkTransactionPreparedCommit,
    ) -> None:
        with self._lock:
            capability = self._claimed_composites.pop(id(prepared), None)
            if capability is not None and capability.prepared_identity != id(prepared):
                raise StateError("Network transaction outer claim identity diverged")

    def _commit_outer_claim_no_fail(
        self,
        prepared: NetworkTransactionPreparedCommit,
    ) -> NetworkTransactionPreparationReceipt:
        """Commit the runtime-owned nested TLS claim and exact runtime overlay."""

        with self._lock:
            composite = self._claimed_composites.get(id(prepared))
            if composite is None or composite.prepared_identity != id(prepared):
                raise StateError("Network transaction outer claim is stale or foreign")
            capability = self._prepared_capabilities.get(id(composite.token))
            if (
                capability is None
                or capability.preparation_id != composite.preparation_id
                or capability.preparation_id not in self._claimed_preparations
            ):
                raise StateError("Network transaction outer claim lost its authority")
            crypto_commit = composite.crypto_commit
            token = composite.token
        cryptographic_receipt = crypto_commit.commit_no_fail()
        return self._commit_claimed_no_fail(
            token,
            cryptographic_receipt=cryptographic_receipt,
        )

    def _cancel_claimed(self, token: NetworkTransactionPreparationToken) -> None:
        crypto_token: CryptographicMaterialPreparationToken | None = None
        with self._lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                return
            if capability.preparation_id not in self._claimed_preparations:
                return
            crypto_token = capability.crypto_token
            self._release_capability_locked(capability)
        if crypto_token is not None:
            self.cryptographic_material.cancel_tls_preparation(crypto_token)

    def _commit_claimed_no_fail(
        self,
        token: NetworkTransactionPreparationToken,
        *,
        cryptographic_receipt: CryptographicMaterialPreparationReceipt,
    ) -> NetworkTransactionPreparationReceipt:
        with self._lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None or capability.preparation_id not in self._claimed_preparations:
                raise StateError("Network transaction token is not claimed for commit")
            # Claim validation and exact-key reservations make these primitive
            # writes structurally no-fail; do not re-run semantic validation.
            tombstone_anchor = max(
                self._watermark,
                capability.trusted_token.linearization_time,
                capability.publication_time,
            )
            for mutation in capability.mutations:
                self._apply_point_mutation_locked(
                    mutation,
                    tombstone_anchor=tombstone_anchor,
                    trusted_value=True,
                )
            self._last_result = capability.trusted_root.result
            receipt = NetworkTransactionPreparationReceipt(
                publication_token=capability.integrity_token,
                transaction_id=capability.trusted_token.transaction_id,
                overlay_digest=capability.trusted_token.overlay_digest,
                committed_runtime_digest=self._state_digest_locked(),
                cryptographic_receipt=cryptographic_receipt,
                committed_point_mutations=len(capability.mutations),
                _runtime_token=id(self),
            )
            receipt = replace(
                receipt,
                _integrity_token=_receipt_integrity(self._secret, receipt),
            )
            self._release_capability_locked(capability)
            return receipt

    def _validate_expectations_locked(
        self,
        expectations: tuple[_PointExpectation, ...],
    ) -> None:
        for expectation in expectations:
            slot = self._points.get((expectation.family, expectation.key))
            if slot is None:
                generation = 0
                value_digest = _MISSING_DIGEST
            else:
                generation = slot.generation
                value_digest = _MISSING_DIGEST if slot.is_tombstone else _value_digest(slot.value)
            if generation != expectation.generation or value_digest != expectation.value_digest:
                raise StateError("Network runtime point changed after preparation")

    def _release_capability_locked(self, capability: _PreparedCapability) -> None:
        active = self._prepared_tokens.pop(capability.preparation_id, None)
        retained = self._prepared_capabilities.pop(capability.token_identity, None)
        self._claimed_preparations.discard(capability.preparation_id)
        self._preparation_fences.remove(capability.preparation_id)
        self._release_point_reservations_locked(capability.preparation_id)
        if active is None or id(active) != capability.token_identity or retained is not capability:
            raise StateError("Network transaction capability ownership diverged")

    def _release_point_reservations_locked(self, preparation_id: int) -> None:
        for point_key in self._reserved_by_preparation.pop(preparation_id, set()):
            if self._reserved_points.get(point_key) == preparation_id:
                self._reserved_points.pop(point_key)
                self._reserved_deadlines.replace(point_key, None)

    def _reject_reserved_point_locked(
        self,
        point_key: tuple[NetworkRuntimePointFamily, Hashable],
    ) -> None:
        if point_key in self._reserved_points:
            raise StateError("Network runtime point has an active preparation")

    def _apply_point_mutation_locked(
        self,
        mutation: _PointMutation,
        *,
        tombstone_anchor: datetime | None = None,
        trusted_value: bool = False,
    ) -> None:
        point_key = (mutation.family, mutation.key)
        prior = self._points.get(point_key)
        prior_component = 0 if prior is None else self._point_slot_state_component(point_key, prior)
        generation = 1 if prior is None else prior.generation + 1
        ordinal = self._next_point_ordinal
        if mutation.kind == "set":
            slot = _PointSlot(
                generation,
                mutation.value if trusted_value else _canonical_value(mutation.value),
                mutation.expires_at,
                None,
                ordinal,
            )
            new_component = self._point_slot_state_component(point_key, slot)
            expiry_entry = None
            if mutation.expires_at != _MAX_TIME:
                expiry_entry = (
                    mutation.expires_at,
                    ordinal,
                    mutation.family,
                    mutation.key,
                    generation,
                    "live",
                )
            if prior is None or prior.is_tombstone:
                self._live_points += 1
            if prior is not None and prior.is_tombstone:
                self._tombstone_points -= 1
            self._next_point_ordinal += 1
            self._points[point_key] = slot
            self._point_state_xor ^= prior_component
            self._point_state_xor ^= new_component
            self._replace_active_expiry_locked(point_key, expiry_entry)
            return

        anchor = tombstone_anchor or self._watermark
        if anchor > _MAX_TIME - self._tombstone_retention:
            tombstone_until = _MAX_TIME
        else:
            tombstone_until = anchor + self._tombstone_retention
        tombstone_until = min(tombstone_until, self._window_end)
        slot = _PointSlot(
            generation,
            None,
            _MAX_TIME,
            tombstone_until,
            ordinal,
        )
        new_component = self._point_slot_state_component(point_key, slot)
        expiry_entry = None
        if tombstone_until != _MAX_TIME:
            expiry_entry = (
                tombstone_until,
                ordinal,
                mutation.family,
                mutation.key,
                generation,
                "tombstone",
            )
        if prior is not None and not prior.is_tombstone:
            self._live_points -= 1
            self._tombstone_points += 1
        elif prior is None:
            self._tombstone_points += 1
        self._next_point_ordinal += 1
        self._points[point_key] = slot
        self._point_state_xor ^= prior_component
        self._point_state_xor ^= new_component
        self._replace_active_expiry_locked(point_key, expiry_entry)

    def _replace_active_expiry_locked(
        self,
        point_key: _PointKey,
        entry: _ExpiryEntry | None,
    ) -> None:
        """Replace one authoritative deadline with exact O(log n) heap work."""

        self._expiry_heap.replace(point_key, entry)

    @staticmethod
    def _expiry_entry_for_slot(
        point_key: _PointKey,
        slot: _PointSlot,
    ) -> _ExpiryEntry | None:
        """Return one slot's finite authoritative deadline, if any."""

        family, key = point_key
        if slot.is_tombstone:
            if slot.tombstone_until == _MAX_TIME:
                return None
            assert slot.tombstone_until is not None
            return (
                slot.tombstone_until,
                slot.ordinal,
                family,
                key,
                slot.generation,
                "tombstone",
            )
        if slot.expires_at == _MAX_TIME:
            return None
        return (
            slot.expires_at,
            slot.ordinal,
            family,
            key,
            slot.generation,
            "live",
        )

    @staticmethod
    def _state_component(label: str, value: object) -> int:
        """Return one deterministic order-independent current-state component."""

        return int.from_bytes(
            hashlib.sha256(repr((label, _freeze_digest_value(value))).encode()).digest(),
            "big",
        )

    def _point_slot_state_component(self, point_key: _PointKey, slot: _PointSlot) -> int:
        """Return the canonical component for one live or tombstone point."""

        return self._state_component(
            "network-runtime-point-v1",
            (
                point_key[0].value,
                point_key[1],
                slot.generation,
                slot.value,
                slot.expires_at,
                slot.tombstone_until,
            ),
        )

    def _state_digest_locked(self) -> str:
        """Return an O(1) digest of deterministic current canonical state."""

        state = (
            "network-runtime-state-v2",
            self._window_start,
            self._window_end,
            self._tombstone_retention,
            self._watermark,
            self._pending_watermark,
            self._point_state_xor,
            self._live_points,
            self._tombstone_points,
            len(self._expiry_heap),
        )
        return hashlib.sha256(repr(_freeze_digest_value(state)).encode()).hexdigest()


__all__ = [
    "NetworkConnectionCommitResult",
    "NetworkCryptographicMaterialPreparation",
    "NetworkRuntimePointFamily",
    "NetworkRuntimeWatermarkPage",
    "NetworkTransactionPreparation",
    "NetworkTransactionPreparationReceipt",
    "NetworkTransactionPreparationToken",
    "NetworkTransactionPreparedCommit",
    "NetworkTransactionRuntime",
    "NetworkTransactionRuntimeCensus",
    "NetworkTransportLifecycleMode",
    "PreparedNetworkTransactionRoot",
]

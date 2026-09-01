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
import ipaddress
import math
import random
import secrets
from collections.abc import Hashable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, fields, replace
from datetime import UTC, datetime, timedelta
from enum import Enum, StrEnum
from threading import RLock, get_ident
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
from evidenceforge.generation.actions.network_identity import (
    _network_transport_occurrence_stable_id,
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
    ConnectionExistingSessionPatch,
    ConnectionExistingSessionProcessRolesPatch,
    ConnectionIdentityPlan,
    ConnectionMaterializationMode,
    ConnectionPlanningCursor,
    MaterializationBatchPlan,
    ProcessActivityPatch,
    SessionActivityPatch,
    SmbConnectionPin,
    SmbFileMutationJournal,
    StateManager,
)
from evidenceforge.models.exceptions import StateError, TransportPortExhaustionError
from evidenceforge.utils.time import ensure_utc

_MAX_TIME = datetime.max.replace(tzinfo=UTC)
_MIN_TIME = datetime.min.replace(tzinfo=UTC)
_MISSING_DIGEST = hashlib.sha256(b"network-runtime:missing").hexdigest()
_TRANSPORT_FRESHNESS_RETENTION = timedelta(hours=24)
_TRANSPORT_FRESH_CANDIDATE_LIMIT = 128
_WINDOWS_EPHEMERAL_PORT_RANGE = (49_152, 65_535)
_LINUX_EPHEMERAL_PORT_RANGE = (32_768, 60_999)

NetworkTransportLifecycleMode = Literal["network", "deferred_session", "application_child"]
_DeferredCompositionKind = Literal["ssh", "rdp"]


def _canonical_datetime(value: datetime, *, field_name: str) -> datetime:
    """Return one exact datetime without invoking caller-defined subclasses."""

    if type(value) is not datetime:
        raise ValueError(f"Network runtime {field_name} must be an exact datetime")
    return ensure_utc(value)


def _canonical_ip(value: str, *, field_name: str) -> str:
    """Return one normalized IP, collapsing IPv4-mapped IPv6 addresses."""

    if type(value) is not str or not value.strip():
        raise ValueError(f"Network runtime {field_name} must be a non-empty IP address")
    normalized = value.strip()
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        # Compatibility callers can carry deterministic pseudo-addresses while
        # stress-testing renderer protocol constraints. Preserve their exact
        # endpoint spelling; scenario validation remains the IP authority.
        return normalized.casefold()
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


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
    KERBEROS_AUDIT_PAIR = "kerberos_audit_pair"
    KERBEROS_AUDIT_TUPLE = "kerberos_audit_tuple"
    AD_SRV_DISCOVERY = "ad_srv_discovery"


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


class _IndexedTransportDeadlineHeap:
    """Exact-key removable deadlines for leases and freshness entries."""

    __slots__ = ("_entries", "_positions")

    def __init__(self) -> None:
        self._entries: list[tuple[datetime, int, Hashable]] = []
        self._positions: dict[Hashable, int] = {}

    def __bool__(self) -> bool:
        return bool(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def first(self) -> tuple[datetime, int, Hashable]:
        if not self._entries:
            raise StateError("Network transport deadline heap is empty")
        return self._entries[0]

    def pop_first(self) -> tuple[datetime, int, Hashable]:
        if not self._entries:
            raise StateError("Network transport deadline heap is empty")
        return self._remove_at(0)

    def replace(
        self,
        key: Hashable,
        entry: tuple[datetime, int, Hashable] | None,
    ) -> None:
        position = self._positions.get(key)
        if entry is None:
            if position is not None:
                self._remove_at(position)
            return
        if entry[2] != key:
            raise StateError("Network transport deadline identity diverged")
        if position is None:
            position = len(self._entries)
            self._entries.append(entry)
            self._positions[key] = position
            self._sift_up(position)
            return
        prior = self._entries[position]
        self._entries[position] = entry
        if entry[:2] < prior[:2]:
            self._sift_up(position)
        else:
            self._sift_down(position)

    def _remove_at(self, position: int) -> tuple[datetime, int, Hashable]:
        removed = self._entries[position]
        last = self._entries.pop()
        self._positions.pop(removed[2])
        if position == len(self._entries):
            return removed
        self._entries[position] = last
        self._positions[last[2]] = position
        if position and last[:2] < self._entries[(position - 1) // 2][:2]:
            self._sift_up(position)
        else:
            self._sift_down(position)
        return removed

    def _sift_up(self, position: int) -> None:
        while position:
            parent = (position - 1) // 2
            if self._entries[parent][:2] <= self._entries[position][:2]:
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
            if right < size and self._entries[right][:2] < self._entries[left][:2]:
                child = right
            if self._entries[position][:2] <= self._entries[child][:2]:
                return
            self._swap(position, child)
            position = child

    def _swap(self, left: int, right: int) -> None:
        self._entries[left], self._entries[right] = self._entries[right], self._entries[left]
        self._positions[self._entries[left][2]] = left
        self._positions[self._entries[right][2]] = right


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
    """Validate the engine-owned immutable commit result once at sealing."""

    _validate_canonical_event_tree(result)
    return result


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
    transport_occurrence_id: str = ""
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
class NetworkPointBatchToken:
    """Opaque owner-authenticated reservation for one point-only overlay."""

    preparation_id: int
    stable_id: str
    linearization_time: datetime
    overlay_digest: str
    point_mutations: int
    _runtime_token: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")

    @property
    def publication_token(self) -> str:
        """Return the stable keyed proof bound into an outer occurrence owner."""

        return self._integrity_token


@dataclass(frozen=True, slots=True)
class NetworkPointBatchReceipt:
    """Authenticated proof that one point-only overlay committed once."""

    publication_token: str
    stable_id: str
    overlay_digest: str
    committed_runtime_digest: str
    committed_point_mutations: int
    _runtime_token: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")

    @property
    def receipt_token(self) -> str:
        """Return the keyed proof over the exact committed point outcome."""

        return self._integrity_token


@dataclass(frozen=True, slots=True)
class PreparedNetworkTransactionRoot:
    """Frozen State and runtime inputs ready for outer-authority composition."""

    transaction: NetworkTransactionPlan
    state_plan: ConnectionCompositeMaterializationPlan
    runtime_token: NetworkTransactionPreparationToken
    result: NetworkConnectionCommitResult


_TransportEndpointKey = tuple[str, str, int, str]
_TransportTupleKey = tuple[str, int, str, int, str]


@dataclass(frozen=True, slots=True)
class NetworkTransportLease:
    """Immutable source-port ownership for one canonical physical transport."""

    intent_stable_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    opened_at: datetime
    closed_at: datetime
    occurrence_stable_id: str
    automatic: bool

    @property
    def tuple_key(self) -> _TransportTupleKey:
        """Return the normalized five-tuple protected by this lease."""

        return (
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol,
        )

    @property
    def endpoint_key(self) -> _TransportEndpointKey:
        """Return the endpoint scope across which source ports are allocated."""

        return self.src_ip, self.dst_ip, self.dst_port, self.protocol


@dataclass(frozen=True, slots=True)
class _TransportLeaseRecord:
    lease: NetworkTransportLease
    preparation_id: int
    candidate_inspections: int
    adaptive_reuse: bool
    committed: bool = False


def _transport_lease_digest_value(lease: NetworkTransportLease) -> tuple[object, ...]:
    """Return one callback-free primitive frame for a committed lease."""

    return (
        lease.intent_stable_id,
        lease.tuple_key,
        lease.opened_at,
        lease.closed_at,
        lease.occurrence_stable_id,
        lease.automatic,
    )


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
    pending_transport_leases: int
    live_transport_leases: int
    retained_transport_freshness: int
    transport_candidate_inspections: int
    peak_transport_bucket_occupancy: int
    adaptive_transport_reuses: int
    transport_exhaustions: int
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
    identity_bound: bool = False


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
class _OpenPointBatchCapability:
    preparation_id: int
    preparation_identity: int
    stable_id: str
    linearization_time: datetime


@dataclass(frozen=True, slots=True)
class _PreparedPointBatchCapability:
    token_identity: int
    preparation_id: int
    integrity_token: str
    trusted_token: NetworkPointBatchToken
    expectations: tuple[_PointExpectation, ...]
    mutations: tuple[_PointMutation, ...]
    reserved_points: tuple[_PointKey, ...]


@dataclass(frozen=True, slots=True)
class _ClaimedCompositeCapability:
    """Runtime-owned nested crypto authority for one public outer claim."""

    prepared_identity: int
    preparation_id: int
    token: NetworkTransactionPreparationToken
    crypto_commit: CryptographicMaterialPreparedCommit


@dataclass(frozen=True, slots=True)
class _ClaimedPointBatchCapability:
    """Runtime-owned authority for one public point-only claim facade."""

    prepared_identity: int
    preparation_id: int
    token: NetworkPointBatchToken
    claim_thread_id: int


@dataclass(frozen=True, slots=True)
class _NetworkDeferredCompositionHandle:
    """Inert internal deferred-composition shape awaiting an RAII owner."""

    kind: _DeferredCompositionKind
    request_id: str
    action_group_id: str


def _token_integrity(secret: bytes, token: NetworkTransactionPreparationToken) -> str:
    del secret
    return hashlib.sha256(
        f"network-transaction:{token._runtime_token:x}:{token.preparation_id:x}".encode()
    ).hexdigest()


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
        or type(token.transport_occurrence_id) is not str
        or type(token._runtime_token) is not int
        or type(token._integrity_token) is not str
    ):
        raise StateError("Network transaction token contains malformed fields")
    try:
        return _token_integrity(secret, token)
    except (AttributeError, TypeError, ValueError) as exc:
        raise StateError("Network transaction token contains malformed fields") from exc


def _receipt_integrity(secret: bytes, receipt: NetworkTransactionPreparationReceipt) -> str:
    del secret
    return hashlib.sha256(
        f"network-receipt:{receipt._runtime_token:x}:{receipt.publication_token}".encode()
    ).hexdigest()


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


def _point_batch_token_integrity(secret: bytes, token: NetworkPointBatchToken) -> str:
    del secret
    return hashlib.sha256(
        f"network-point:{token._runtime_token:x}:{token.preparation_id:x}".encode()
    ).hexdigest()


def _validated_point_batch_token_integrity(
    secret: bytes,
    token: NetworkPointBatchToken,
) -> str:
    """Return point-batch token integrity or reject malformed caller fields."""

    if (
        type(token) is not NetworkPointBatchToken
        or type(token.preparation_id) is not int
        or token.preparation_id <= 0
        or type(token.stable_id) is not str
        or not token.stable_id
        or type(token.linearization_time) is not datetime
        or token.linearization_time.tzinfo is not UTC
        or type(token.overlay_digest) is not str
        or type(token.point_mutations) is not int
        or token.point_mutations < 0
        or type(token._runtime_token) is not int
        or type(token._integrity_token) is not str
    ):
        raise StateError("Network point-batch token contains malformed fields")
    try:
        return _point_batch_token_integrity(secret, token)
    except (AttributeError, TypeError, ValueError) as exc:
        raise StateError("Network point-batch token contains malformed fields") from exc


def _point_batch_receipt_integrity(secret: bytes, receipt: NetworkPointBatchReceipt) -> str:
    del secret
    return hashlib.sha256(
        f"network-point-receipt:{receipt._runtime_token:x}:{receipt.publication_token}".encode()
    ).hexdigest()


def _validated_point_batch_receipt_integrity(
    secret: bytes,
    receipt: NetworkPointBatchReceipt,
) -> str:
    """Return point-batch receipt integrity or reject malformed caller fields."""

    if (
        type(receipt) is not NetworkPointBatchReceipt
        or type(receipt.publication_token) is not str
        or type(receipt.stable_id) is not str
        or not receipt.stable_id
        or type(receipt.overlay_digest) is not str
        or type(receipt.committed_runtime_digest) is not str
        or type(receipt.committed_point_mutations) is not int
        or receipt.committed_point_mutations < 0
        or type(receipt._runtime_token) is not int
        or type(receipt._integrity_token) is not str
    ):
        raise StateError("Network point-batch receipt contains malformed fields")
    try:
        return _point_batch_receipt_integrity(secret, receipt)
    except (AttributeError, TypeError, ValueError) as exc:
        raise StateError("Network point-batch receipt contains malformed fields") from exc


class NetworkPointBatch:
    """Open copy-on-write planner for atomic point-only publication."""

    __slots__ = (
        "_cancelled",
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
    ) -> None:
        self._owner = owner
        self._preparation_id = preparation_id
        self._stable_id = stable_id
        self._linearization_time = linearization_time
        self._expectations: dict[_PointKey, _PointExpectation] = {}
        self._mutations: dict[_PointKey, _PointMutation] = {}
        self._sealed = False
        self._cancelled = False

    @property
    def preparation_id(self) -> int:
        """Return this runtime's monotonic preparation identifier."""

        return self._preparation_id

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
        expectation, value, expires_at, visible = self._owner._reserve_point_batch_point(
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
        point_key = (canonical_family, canonical_key)
        if point_key in self._mutations:
            raise StateError("Network point batch contains a duplicate mutation")
        self._owner._validate_point_batch_expiry(self, canonical_expiry)
        if point_key not in self._expectations:
            expectation, _value, _expires_at, _visible = self._owner._reserve_point_batch_point(
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
        """Stage one exact deletion while retaining an ABA generation."""

        self._require_open()
        canonical_family = _canonical_family(family)
        canonical_key = _canonical_key(key)
        point_key = (canonical_family, canonical_key)
        if point_key in self._mutations:
            raise StateError("Network point batch contains a duplicate mutation")
        if point_key not in self._expectations:
            expectation, _value, _expires_at, _visible = self._owner._reserve_point_batch_point(
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

    def seal(self) -> NetworkPointBatchToken:
        """Seal an exact point overlay without publishing it."""

        self._require_open()
        try:
            token = self._owner._seal_point_batch(self)
        except BaseException:
            self._abort_failed_seal()
            raise
        self._sealed = True
        return token

    def cancel(self) -> None:
        """Cancel this open batch without changing canonical point state."""

        self._require_open()
        self._owner._cancel_open_point_batch(self)
        self._cancelled = True

    def _abort_failed_seal(self) -> None:
        try:
            self._owner._cancel_open_point_batch(self)
        except StateError:
            pass
        self._cancelled = True

    def _require_open(self) -> None:
        if self._cancelled:
            raise StateError("Network point batch is cancelled")
        if self._sealed:
            raise StateError("Network point batch is already sealed")


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

    def bind_transaction_identity(self, stable_id: str) -> None:
        """Bind the open preparation to its finalized canonical transaction ID."""

        self._require_open()
        self._owner._bind_transaction_identity(self, stable_id)

    def reserve_transport_tuple(
        self,
        *,
        intent_stable_id: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        opened_at: datetime,
        closed_at: datetime,
        source_port: int | None = None,
        preferred_source_port: int | None = None,
        source_os_category: str = "windows",
        port_range: tuple[int, int] | None = None,
    ) -> NetworkTransportLease:
        """Atomically lease one exact physical transport tuple and interval."""

        self._require_open()
        return self._owner._reserve_transport_tuple(
            self,
            intent_stable_id=intent_stable_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            opened_at=opened_at,
            closed_at=closed_at,
            source_port=source_port,
            preferred_source_port=preferred_source_port,
            source_os_category=source_os_category,
            port_range=port_range,
        )

    def reserve_smb_connection_pin(self) -> SmbConnectionPin:
        """Reserve the future persistent-SMB pin through the owned State cursor."""

        self._require_open()
        return self._owner._reserve_smb_connection_pin(self)

    def terminalize_smb_file_mutation(self, journal: SmbFileMutationJournal) -> None:
        """Attach one authenticated SMB file journal to the physical root."""

        self._require_open()
        self._owner._terminalize_smb_file_mutation(self, journal)

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
        rdp_existing_session_patch: ConnectionExistingSessionPatch | None = None,
        existing_session_process_roles_patch: (
            ConnectionExistingSessionProcessRolesPatch | None
        ) = None,
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
                if rdp_existing_session_patch is not None and lifecycle_mode != "deferred_session":
                    raise StateError(
                        "RDP existing-session patch requires deferred_session lifecycle mode"
                    )
                if (
                    existing_session_process_roles_patch is not None
                    and lifecycle_mode != "deferred_session"
                ):
                    raise StateError(
                        "Existing-session process roles require deferred_session lifecycle mode"
                    )
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
            state_transaction = trusted_transaction

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
                rdp_existing_session_patch=rdp_existing_session_patch,
                existing_session_process_roles_patch=(existing_session_process_roles_patch),
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


class NetworkPointBatchPreparedCommit:
    """Claim facade for one structurally no-fail point-only commit."""

    __slots__ = ("_active", "_committed", "_owner", "_receipt")

    def __init__(self, owner: NetworkTransactionRuntime) -> None:
        self._owner = owner
        self._active = True
        self._committed = False
        self._receipt: NetworkPointBatchReceipt | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact claim committed once."""

        return self._committed

    @property
    def receipt(self) -> NetworkPointBatchReceipt | None:
        """Return the signed receipt after commit."""

        return self._receipt

    def commit_no_fail(self) -> NetworkPointBatchReceipt:
        """Publish every prevalidated primitive point write atomically."""

        if not self._active:
            raise StateError("Network point-batch prepared commit is no longer active")
        if self._committed:
            raise StateError("Network point batch was already committed")
        receipt = self._owner._commit_point_batch_claim_no_fail(self)
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
        self._open_point_batches: dict[int, _OpenPointBatchCapability] = {}
        self._open_point_batch_objects: dict[int, NetworkPointBatch] = {}
        self._open_point_batch_capabilities_by_identity: dict[int, _OpenPointBatchCapability] = {}
        self._prepared_tokens: dict[int, NetworkTransactionPreparationToken] = {}
        self._prepared_capabilities: dict[int, _PreparedCapability] = {}
        self._point_batch_tokens: dict[int, NetworkPointBatchToken] = {}
        self._point_batch_capabilities: dict[int, _PreparedPointBatchCapability] = {}
        self._claimed_preparations: set[int] = set()
        self._claimed_composites: dict[int, _ClaimedCompositeCapability] = {}
        self._claimed_point_batches: set[int] = set()
        self._claimed_point_batch_commits: dict[int, _ClaimedPointBatchCapability] = {}
        self._reserved_points: dict[tuple[NetworkRuntimePointFamily, Hashable], int] = {}
        self._reserved_by_preparation: dict[
            int, set[tuple[NetworkRuntimePointFamily, Hashable]]
        ] = {}
        self._last_result: NetworkConnectionCommitResult | None = None
        self._point_state_xor = 0
        self._transport_buckets: dict[_TransportTupleKey, list[_TransportLeaseRecord]] = {}
        self._transport_endpoint_occurrences: dict[_TransportEndpointKey, set[str]] = {}
        self._transport_records_by_occurrence: dict[str, _TransportLeaseRecord] = {}
        self._transport_records_by_preparation: dict[int, _TransportLeaseRecord] = {}
        self._adopted_transport_by_preparation: dict[int, str] = {}
        self._transport_lease_deadlines = _IndexedTransportDeadlineHeap()
        self._transport_freshness: dict[_TransportTupleKey, datetime] = {}
        self._transport_freshness_deadlines = _IndexedTransportDeadlineHeap()
        self._next_transport_ordinal = 1
        self._pending_transport_leases = 0
        self._live_transport_leases = 0
        self._transport_candidate_inspections = 0
        self._peak_transport_bucket_occupancy = 0
        self._adaptive_transport_reuses = 0
        self._transport_exhaustions = 0
        self._transport_state_xor = 0

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

    def begin_point_batch(
        self,
        *,
        stable_id: str,
        linearization_time: datetime,
    ) -> NetworkPointBatch:
        """Begin one allocation-free point-only preparation."""

        if type(stable_id) is not str or not stable_id.strip():
            raise ValueError("Network point-batch stable_id must not be empty")
        canonical_time = _canonical_datetime(
            linearization_time,
            field_name="point-batch linearization_time",
        )
        with self._lock:
            fence = self._pending_watermark or self._watermark
            if canonical_time < fence:
                raise StateError("Network point-batch preparation starts behind the watermark")
            if canonical_time >= self._window_end:
                raise StateError(
                    "Network point-batch preparation starts at or after the runtime window end"
                )
            preparation_id = self._next_preparation_id
            self._next_preparation_id += 1
            preparation = NetworkPointBatch(
                self,
                preparation_id=preparation_id,
                stable_id=stable_id,
                linearization_time=canonical_time,
            )
            capability = _OpenPointBatchCapability(
                preparation_id=preparation_id,
                preparation_identity=id(preparation),
                stable_id=stable_id,
                linearization_time=canonical_time,
            )
            self._open_point_batches[preparation_id] = capability
            self._open_point_batch_objects[id(preparation)] = preparation
            self._open_point_batch_capabilities_by_identity[id(preparation)] = capability
            self._preparation_fences.set(preparation_id, canonical_time)
            return preparation

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

    def transport_tuple_last_seen_at(
        self,
        *,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
    ) -> datetime | None:
        """Return the latest committed canonical observation for one five-tuple."""

        canonical_src = _canonical_ip(src_ip, field_name="transport source IP")
        canonical_dst = _canonical_ip(dst_ip, field_name="transport destination IP")
        if type(src_port) is not int or not 1 <= src_port <= 65_535:
            raise ValueError("Transport source port must be between 1 and 65535")
        if type(dst_port) is not int or not 0 <= dst_port <= 65_535:
            raise ValueError("Transport destination port must be between 0 and 65535")
        if type(protocol) is not str or protocol.casefold() not in {"tcp", "udp"}:
            raise ValueError("Transport protocol must be TCP or UDP")
        tuple_key = (
            canonical_src,
            src_port,
            canonical_dst,
            dst_port,
            protocol.casefold(),
        )
        with self._lock:
            seen_at = self._transport_freshness.get(tuple_key)
            compatibility_slot = self._points.get(
                (NetworkRuntimePointFamily.RECENT_TUPLE, tuple_key)
            )
            if (
                compatibility_slot is not None
                and not compatibility_slot.is_tombstone
                and type(compatibility_slot.value) is float
            ):
                compatibility_seen_at = datetime.fromtimestamp(
                    compatibility_slot.value,
                    tz=UTC,
                )
                seen_at = max(seen_at or compatibility_seen_at, compatibility_seen_at)
            bucket = self._transport_buckets.get(tuple_key)
            if bucket:
                committed_closes = (
                    record.lease.closed_at for record in reversed(bucket) if record.committed
                )
                latest_close = next(committed_closes, None)
                if latest_close is not None:
                    seen_at = max(seen_at or latest_close, latest_close)
            return seen_at

    def transport_tuple_interval_available(
        self,
        *,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        opened_at: datetime,
        closed_at: datetime,
    ) -> bool:
        """Return whether committed and pending leases leave one interval free."""

        canonical_src = _canonical_ip(src_ip, field_name="transport source IP")
        canonical_dst = _canonical_ip(dst_ip, field_name="transport destination IP")
        if type(src_port) is not int or not 1 <= src_port <= 65_535:
            raise ValueError("Transport source port must be between 1 and 65535")
        if type(dst_port) is not int or not 0 <= dst_port <= 65_535:
            raise ValueError("Transport destination port must be between 0 and 65535")
        if type(protocol) is not str or protocol.casefold() not in {"tcp", "udp"}:
            raise ValueError("Transport protocol must be TCP or UDP")
        canonical_open = _canonical_datetime(opened_at, field_name="transport opening time")
        canonical_close = _canonical_datetime(closed_at, field_name="transport closing time")
        if canonical_close < canonical_open:
            raise ValueError("Transport closing time cannot precede its opening time")
        tuple_key = (
            canonical_src,
            src_port,
            canonical_dst,
            dst_port,
            protocol.casefold(),
        )
        with self._lock:
            return self._transport_interval_available_locked(
                tuple_key,
                canonical_open,
                canonical_close,
            )

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

    def cancel_point_batch(self, token: NetworkPointBatchToken) -> bool:
        """Cancel one unclaimed sealed point batch and release its reservations."""

        if type(token) is not NetworkPointBatchToken:
            return False
        error: StateError | None = None
        with self._lock:
            capability = self._point_batch_capabilities.get(id(token))
            if capability is None:
                return False
            if capability.preparation_id in self._claimed_point_batches:
                return False
            try:
                capability = self._active_point_batch_capability_locked(token)
            except StateError as exc:
                self._release_point_batch_capability_locked(capability)
                error = exc
            else:
                self._release_point_batch_capability_locked(capability)
        if error is not None:
            raise error
        return True

    def authenticates_point_batch_token(
        self,
        token: NetworkPointBatchToken,
        *,
        expected_stable_id: str | None = None,
    ) -> bool:
        """Return whether this runtime owns one intact active point-batch token."""

        if type(token) is not NetworkPointBatchToken:
            return False
        try:
            with self._lock:
                capability = self._active_point_batch_capability_locked(token)
                if (
                    expected_stable_id is not None
                    and capability.trusted_token.stable_id != expected_stable_id
                ):
                    return False
                return True
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

    def authenticates_point_batch_receipt(
        self,
        receipt: NetworkPointBatchReceipt,
        *,
        token: NetworkPointBatchToken | None = None,
    ) -> bool:
        """Authenticate one exact point-batch receipt and optional issuing token."""

        if type(receipt) is not NetworkPointBatchReceipt:
            return False
        try:
            expected = _validated_point_batch_receipt_integrity(self._secret, receipt)
            if receipt._runtime_token != id(self) or receipt.receipt_token != expected:
                return False
            if token is None:
                return True
            if type(token) is not NetworkPointBatchToken:
                return False
            expected_token = _validated_point_batch_token_integrity(self._secret, token)
            if token._runtime_token != id(self) or token.publication_token != expected_token:
                return False
            return (
                receipt.publication_token == token.publication_token
                and receipt.stable_id == token.stable_id
                and receipt.overlay_digest == token.overlay_digest
                and receipt.committed_point_mutations == token.point_mutations
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

    @contextmanager
    def claimed_point_batch(
        self,
        token: NetworkPointBatchToken,
    ) -> Iterator[NetworkPointBatchPreparedCommit]:
        """Claim one point-only token without retaining the runtime lock."""

        capability = self._claim_point_batch(token)
        try:
            prepared = NetworkPointBatchPreparedCommit(self)
            self._register_claimed_point_batch(
                prepared,
                capability=capability,
                token=token,
            )
            try:
                yield prepared
            finally:
                if not prepared.committed:
                    self._cancel_claimed_point_batch(token)
                self._close_claimed_point_batch(prepared)
                prepared._close()
        except BaseException:
            self._cancel_claimed_point_batch(token)
            raise

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
        """Return whether this runtime owns one exact active preparation root."""

        if type(root) is not PreparedNetworkTransactionRoot:
            return False
        token = root.runtime_token
        if type(token) is not NetworkTransactionPreparationToken:
            return False

        with self._lock:
            try:
                capability = self._active_capability_locked(token)
            except StateError:
                return False
            if root is not capability.trusted_root:
                return False
            crypto_token = capability.crypto_token
            state_plan = capability.trusted_root.state_plan
        return self.state_manager.authenticates_materialization_plan(
            state_plan
        ) and self.cryptographic_material.authenticates_tls_preparation_token(crypto_token)

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
        if receipt._integrity_token != expected:
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
            if token.publication_token != expected_token:
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
                self._transport_lease_deadlines
                and self._transport_lease_deadlines.first()[0] <= canonical_cutoff
                and work < limit
            ):
                _deadline, _ordinal, occurrence_id = self._transport_lease_deadlines.pop_first()
                if type(occurrence_id) is not str:
                    raise StateError("Transport lease deadline contains an invalid occurrence ID")
                record = self._transport_records_by_occurrence.get(occurrence_id)
                if record is None or not record.committed:
                    raise StateError("Transport lease deadline lost its committed occurrence")
                self._transport_state_xor ^= self._state_component(
                    "network-transport-lease-v1",
                    _transport_lease_digest_value(record.lease),
                )
                self._remove_transport_record_locked(record)
                self._live_transport_leases -= 1
                work += 1
                processed += 1
            while (
                self._transport_freshness_deadlines
                and self._transport_freshness_deadlines.first()[0] <= canonical_cutoff
                and work < limit
            ):
                _deadline, _ordinal, tuple_key = self._transport_freshness_deadlines.pop_first()
                if type(tuple_key) is not tuple or len(tuple_key) != 5:
                    raise StateError("Transport freshness deadline contains an invalid tuple")
                seen_at = self._transport_freshness.pop(tuple_key, None)
                if seen_at is None:
                    raise StateError("Transport freshness deadline lost its tuple")
                self._transport_state_xor ^= self._state_component(
                    "network-transport-freshness-v1",
                    (tuple_key, seen_at),
                )
                work += 1
                processed += 1
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
            has_more = bool(
                (
                    self._transport_lease_deadlines
                    and self._transport_lease_deadlines.first()[0] <= canonical_cutoff
                )
                or (
                    self._transport_freshness_deadlines
                    and self._transport_freshness_deadlines.first()[0] <= canonical_cutoff
                )
                or (self._expiry_heap and self._expiry_heap.first()[0] <= canonical_cutoff)
            )
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
            open_preparations=len(self._open_preparations) + len(self._open_point_batches),
            prepared_transactions=len(self._prepared_tokens) + len(self._point_batch_tokens),
            claimed_transactions=len(self._claimed_preparations) + len(self._claimed_point_batches),
            reserved_points=len(self._reserved_points),
            preparation_fences=len(self._preparation_fences),
            reserved_deadlines=len(self._reserved_deadlines),
            active_deadlines=len(self._expiry_heap),
            expiry_backing=(
                len(self._expiry_heap)
                + len(self._transport_lease_deadlines)
                + len(self._transport_freshness_deadlines)
            ),
            pending_transport_leases=self._pending_transport_leases,
            live_transport_leases=self._live_transport_leases,
            retained_transport_freshness=len(self._transport_freshness),
            transport_candidate_inspections=self._transport_candidate_inspections,
            peak_transport_bucket_occupancy=self._peak_transport_bucket_occupancy,
            adaptive_transport_reuses=self._adaptive_transport_reuses,
            transport_exhaustions=self._transport_exhaustions,
            watermark=self._watermark,
            pending_watermark=self._pending_watermark,
            has_last_result=self._last_result is not None,
        )

    def _preparation_rng(self, preparation: NetworkTransactionPreparation) -> Any:
        """Return the State-owned isolated RNG without exposing its cursor."""

        with self._lock:
            cursor = self._active_open_preparation_locked(preparation).cursor
        return cursor.rng

    def _reserve_transport_tuple(
        self,
        preparation: NetworkTransactionPreparation,
        *,
        intent_stable_id: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        opened_at: datetime,
        closed_at: datetime,
        source_port: int | None,
        preferred_source_port: int | None,
        source_os_category: str,
        port_range: tuple[int, int] | None,
    ) -> NetworkTransportLease:
        """Select and claim one tuple while holding the canonical runtime lock."""

        if type(intent_stable_id) is not str or not intent_stable_id.strip():
            raise ValueError("Transport lease intent_stable_id must not be empty")
        canonical_src = _canonical_ip(src_ip, field_name="transport source IP")
        canonical_dst = _canonical_ip(dst_ip, field_name="transport destination IP")
        if type(dst_port) is not int or not 0 <= dst_port <= 65_535:
            raise ValueError("Transport lease destination port must be between 0 and 65535")
        if type(protocol) is not str or protocol.casefold() not in {"tcp", "udp"}:
            raise ValueError("Transport leases support only TCP or UDP")
        canonical_protocol = protocol.casefold()
        canonical_open = _canonical_datetime(opened_at, field_name="transport opening time")
        canonical_close = _canonical_datetime(closed_at, field_name="transport closing time")
        if canonical_close < canonical_open:
            raise ValueError("Transport lease closing time cannot precede its opening time")
        if canonical_open < self._window_start or canonical_open >= self._window_end:
            raise StateError("Transport lease starts outside the runtime window")
        if canonical_close > self._window_end:
            raise StateError("Transport lease closes after the runtime window")
        if source_port is not None and (
            type(source_port) is not int or not 1 <= source_port <= 65_535
        ):
            raise ValueError("Exact transport source port must be between 1 and 65535")
        if preferred_source_port is not None and (
            type(preferred_source_port) is not int or not 1 <= preferred_source_port <= 65_535
        ):
            raise ValueError("Preferred transport source port must be between 1 and 65535")
        if source_port is not None and preferred_source_port is not None:
            raise ValueError("Exact and preferred transport source ports are mutually exclusive")
        if type(source_os_category) is not str:
            raise ValueError("Transport source OS category must be a string")
        selected_range = port_range
        if selected_range is None:
            selected_range = (
                _LINUX_EPHEMERAL_PORT_RANGE
                if source_os_category.casefold() == "linux"
                else _WINDOWS_EPHEMERAL_PORT_RANGE
            )
        if (
            type(selected_range) is not tuple
            or len(selected_range) != 2
            or type(selected_range[0]) is not int
            or type(selected_range[1]) is not int
            or selected_range[0] < 1
            or selected_range[1] > 65_535
            or selected_range[1] < selected_range[0]
        ):
            raise ValueError("Transport source-port range must be an inclusive valid port pair")

        endpoint_key = (canonical_src, canonical_dst, dst_port, canonical_protocol)
        with self._lock:
            capability = self._active_open_preparation_locked(preparation)
            existing = self._transport_records_by_preparation.get(capability.preparation_id)
            adopted_occurrence = self._adopted_transport_by_preparation.get(
                capability.preparation_id
            )
            if existing is not None or adopted_occurrence is not None:
                retained = (
                    existing
                    if existing is not None
                    else self._transport_records_by_occurrence.get(adopted_occurrence or "")
                )
                if retained is None:
                    raise StateError("Transport lease adoption lost its committed occurrence")
                requested_port = retained.lease.src_port if source_port is None else source_port
                if (
                    retained.lease.intent_stable_id != intent_stable_id
                    or retained.lease.endpoint_key != endpoint_key
                    or retained.lease.src_port != requested_port
                    or retained.lease.opened_at != canonical_open
                    or retained.lease.closed_at != canonical_close
                ):
                    raise StateError("Network preparation already owns a different transport lease")
                return retained.lease

            if source_port is not None:
                exact_occurrence_id = _network_transport_occurrence_stable_id(
                    intent_stable_id,
                    src_ip=canonical_src,
                    src_port=source_port,
                    dst_ip=canonical_dst,
                    dst_port=dst_port,
                    protocol=canonical_protocol,
                    opened_at=canonical_open,
                )
                exact_prior = self._transport_records_by_occurrence.get(exact_occurrence_id)
                if exact_prior is not None and exact_prior.committed:
                    exact_lease = exact_prior.lease
                    if exact_lease.closed_at != canonical_close:
                        raise StateError("Exact transport retry changed its canonical interval")
                    self._adopted_transport_by_preparation[capability.preparation_id] = (
                        exact_occurrence_id
                    )
                    self._bind_transport_identity_locked(
                        preparation,
                        capability,
                        exact_occurrence_id,
                    )
                    return exact_lease

            automatic = source_port is None
            selected_port: int | None = None
            adaptive = False
            allocation_seed = int.from_bytes(
                hashlib.sha256(
                    repr(
                        (
                            "network-transport-allocation-v1",
                            intent_stable_id,
                            endpoint_key,
                            canonical_open,
                            canonical_close,
                            selected_range,
                        )
                    ).encode()
                ).digest(),
                "big",
            )
            rng = random.Random(allocation_seed)
            candidate_inspections = 0
            if source_port is not None:
                candidate_inspections += 1
                tuple_key = (
                    canonical_src,
                    source_port,
                    canonical_dst,
                    dst_port,
                    canonical_protocol,
                )
                if self._transport_interval_available_locked(
                    tuple_key,
                    canonical_open,
                    canonical_close,
                ):
                    selected_port = source_port
            else:
                low, high = selected_range
                fresh_candidates = (
                    (preferred_source_port,) if preferred_source_port is not None else ()
                )
                for candidate_index in range(_TRANSPORT_FRESH_CANDIDATE_LIMIT):
                    candidate = (
                        fresh_candidates[candidate_index]
                        if candidate_index < len(fresh_candidates)
                        else rng.randint(low, high)
                    )
                    if candidate < low or candidate > high:
                        continue
                    candidate_inspections += 1
                    tuple_key = (
                        canonical_src,
                        candidate,
                        canonical_dst,
                        dst_port,
                        canonical_protocol,
                    )
                    if self._transport_tuple_is_fresh_locked(tuple_key, canonical_open):
                        continue
                    if self._transport_interval_available_locked(
                        tuple_key,
                        canonical_open,
                        canonical_close,
                    ):
                        selected_port = candidate
                        break
                if selected_port is None:
                    size = high - low + 1
                    start = rng.randrange(size)
                    stride = rng.randrange(1, size + 1)
                    while math.gcd(stride, size) != 1:
                        stride = 1 if stride == size else stride + 1
                    for offset in range(size):
                        candidate = low + ((start + offset * stride) % size)
                        candidate_inspections += 1
                        tuple_key = (
                            canonical_src,
                            candidate,
                            canonical_dst,
                            dst_port,
                            canonical_protocol,
                        )
                        if self._transport_interval_available_locked(
                            tuple_key,
                            canonical_open,
                            canonical_close,
                        ):
                            selected_port = candidate
                            adaptive = True
                            break

            if selected_port is None:
                self._transport_exhaustions += 1
                raise TransportPortExhaustionError(
                    endpoint_key=endpoint_key,
                    opened_at=canonical_open,
                    closed_at=canonical_close,
                    port_range=selected_range,
                    active_count=self._active_transport_count_locked(
                        endpoint_key,
                        canonical_open,
                        canonical_close,
                    ),
                    automatic=automatic,
                )

            occurrence_id = _network_transport_occurrence_stable_id(
                intent_stable_id,
                src_ip=canonical_src,
                src_port=selected_port,
                dst_ip=canonical_dst,
                dst_port=dst_port,
                protocol=canonical_protocol,
                opened_at=canonical_open,
            )
            prior = self._transport_records_by_occurrence.get(occurrence_id)
            if prior is not None:
                candidate_lease = prior.lease
                if (
                    not prior.committed
                    or candidate_lease.intent_stable_id != intent_stable_id
                    or candidate_lease.tuple_key
                    != (
                        canonical_src,
                        selected_port,
                        canonical_dst,
                        dst_port,
                        canonical_protocol,
                    )
                    or candidate_lease.opened_at != canonical_open
                    or candidate_lease.closed_at != canonical_close
                ):
                    raise StateError("Transport occurrence identity collides with another lease")
                self._adopted_transport_by_preparation[capability.preparation_id] = occurrence_id
                self._bind_transport_identity_locked(preparation, capability, occurrence_id)
                return candidate_lease

            lease = NetworkTransportLease(
                intent_stable_id=intent_stable_id,
                src_ip=canonical_src,
                src_port=selected_port,
                dst_ip=canonical_dst,
                dst_port=dst_port,
                protocol=canonical_protocol,
                opened_at=canonical_open,
                closed_at=canonical_close,
                occurrence_stable_id=occurrence_id,
                automatic=automatic,
            )
            record = _TransportLeaseRecord(
                lease=lease,
                preparation_id=capability.preparation_id,
                candidate_inspections=candidate_inspections,
                adaptive_reuse=adaptive,
            )
            self._insert_transport_record_locked(record)
            self._transport_records_by_preparation[capability.preparation_id] = record
            self._pending_transport_leases += 1
            self._bind_transport_identity_locked(preparation, capability, occurrence_id)
            return lease

    def _bind_transport_identity_locked(
        self,
        preparation: NetworkTransactionPreparation,
        capability: _OpenPreparationCapability,
        occurrence_id: str,
    ) -> None:
        """Bind a lease-owned occurrence without dropping the runtime lock."""

        if capability.identity_bound:
            if capability.stable_id != occurrence_id or preparation._stable_id != occurrence_id:
                raise StateError("Network preparation identity disagrees with its transport lease")
            return
        rebound = replace(capability, stable_id=occurrence_id, identity_bound=True)
        preparation._stable_id = occurrence_id
        self._open_preparations[capability.preparation_id] = rebound
        self._open_capabilities_by_identity[id(preparation)] = rebound

    def _transport_tuple_is_fresh_locked(
        self,
        tuple_key: _TransportTupleKey,
        opened_at: datetime,
    ) -> bool:
        seen_at = self._transport_freshness.get(tuple_key)
        compatibility_slot = self._points.get((NetworkRuntimePointFamily.RECENT_TUPLE, tuple_key))
        if (
            compatibility_slot is not None
            and not compatibility_slot.is_tombstone
            and compatibility_slot.expires_at > opened_at
            and type(compatibility_slot.value) is float
        ):
            compatibility_seen_at = datetime.fromtimestamp(
                compatibility_slot.value,
                tz=UTC,
            )
            seen_at = max(seen_at or compatibility_seen_at, compatibility_seen_at)
        return seen_at is not None and abs(opened_at - seen_at) <= _TRANSPORT_FRESHNESS_RETENTION

    def _transport_interval_available_locked(
        self,
        tuple_key: _TransportTupleKey,
        opened_at: datetime,
        closed_at: datetime,
    ) -> bool:
        bucket = self._transport_buckets.get(tuple_key)
        if not bucket or closed_at == opened_at:
            return True
        low = 0
        high = len(bucket)
        while low < high:
            middle = (low + high) // 2
            if bucket[middle].lease.opened_at < opened_at:
                low = middle + 1
            else:
                high = middle
        for index in (low - 1, low):
            if index < 0 or index >= len(bucket):
                continue
            lease = bucket[index].lease
            if lease.opened_at < closed_at and opened_at < lease.closed_at:
                return False
        return True

    def _insert_transport_record_locked(self, record: _TransportLeaseRecord) -> None:
        lease = record.lease
        self._transport_records_by_occurrence[lease.occurrence_stable_id] = record
        if lease.opened_at == lease.closed_at:
            return
        bucket = self._transport_buckets.setdefault(lease.tuple_key, [])
        low = 0
        high = len(bucket)
        order = (lease.opened_at, lease.occurrence_stable_id)
        while low < high:
            middle = (low + high) // 2
            candidate = bucket[middle].lease
            if (candidate.opened_at, candidate.occurrence_stable_id) < order:
                low = middle + 1
            else:
                high = middle
        bucket.insert(low, record)
        self._transport_endpoint_occurrences.setdefault(lease.endpoint_key, set()).add(
            lease.occurrence_stable_id
        )

    def _remove_transport_record_locked(self, record: _TransportLeaseRecord) -> None:
        lease = record.lease
        if lease.opened_at == lease.closed_at:
            self._transport_records_by_occurrence.pop(lease.occurrence_stable_id, None)
            return
        bucket = self._transport_buckets.get(lease.tuple_key)
        if bucket is None:
            raise StateError("Transport lease bucket disappeared")
        for index, candidate in enumerate(bucket):
            if candidate.lease.occurrence_stable_id == lease.occurrence_stable_id:
                bucket.pop(index)
                break
        else:
            raise StateError("Transport lease bucket lost its occurrence")
        if not bucket:
            self._transport_buckets.pop(lease.tuple_key)
        endpoint_occurrences = self._transport_endpoint_occurrences.get(lease.endpoint_key)
        if endpoint_occurrences is None:
            raise StateError("Transport endpoint index disappeared")
        endpoint_occurrences.discard(lease.occurrence_stable_id)
        if not endpoint_occurrences:
            self._transport_endpoint_occurrences.pop(lease.endpoint_key)
        self._transport_records_by_occurrence.pop(lease.occurrence_stable_id, None)

    def _active_transport_count_locked(
        self,
        endpoint_key: _TransportEndpointKey,
        opened_at: datetime,
        closed_at: datetime,
    ) -> int:
        count = 0
        for occurrence_id in self._transport_endpoint_occurrences.get(endpoint_key, set()):
            record = self._transport_records_by_occurrence.get(occurrence_id)
            if record is None:
                raise StateError("Transport endpoint index contains a stale occurrence")
            lease = record.lease
            if lease.opened_at < closed_at and opened_at < lease.closed_at:
                count += 1
        return count

    def _reserve_physical_identity(
        self,
        preparation: NetworkTransactionPreparation,
    ) -> ConnectionIdentityPlan:
        """Reserve one physical identity through the runtime-owned State cursor."""

        with self._lock:
            cursor = self._active_open_preparation_locked(preparation).cursor
        return cursor.reserve_identity()

    def _reserve_smb_connection_pin(
        self,
        preparation: NetworkTransactionPreparation,
    ) -> SmbConnectionPin:
        """Reserve one persistent-SMB pin through the runtime-owned State cursor."""

        with self._lock:
            cursor = self._active_open_preparation_locked(preparation).cursor
        return cursor.reserve_smb_connection_pin()

    def _terminalize_smb_file_mutation(
        self,
        preparation: NetworkTransactionPreparation,
        journal: SmbFileMutationJournal,
    ) -> None:
        """Bind one SMB file terminalization through the runtime-owned State cursor."""

        with self._lock:
            cursor = self._active_open_preparation_locked(preparation).cursor
        cursor.terminalize_smb_file_mutation(journal)

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
        rdp_existing_session_patch: ConnectionExistingSessionPatch | None,
        existing_session_process_roles_patch: ConnectionExistingSessionProcessRolesPatch | None,
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
            rdp_existing_session_patch=rdp_existing_session_patch,
            existing_session_process_roles_patch=existing_session_process_roles_patch,
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
            return self._reserve_point_locked(
                preparation_id=capability.preparation_id,
                point_key=point_key,
            )

    def _reserve_point_batch_point(
        self,
        preparation: NetworkPointBatch,
        family: NetworkRuntimePointFamily,
        key: Hashable,
    ) -> tuple[_PointExpectation, object | None, datetime, bool]:
        point_key = (family, key)
        with self._lock:
            capability = self._active_open_point_batch_locked(preparation)
            return self._reserve_point_locked(
                preparation_id=capability.preparation_id,
                point_key=point_key,
            )

    def _reserve_point_locked(
        self,
        *,
        preparation_id: int,
        point_key: _PointKey,
    ) -> tuple[_PointExpectation, object | None, datetime, bool]:
        """Reserve one canonical key for an already-authenticated open owner."""

        family, key = point_key
        owner = self._reserved_points.get(point_key)
        if owner is not None and owner != preparation_id:
            raise StateError("Network runtime point is reserved by another preparation")
        self._reserved_points[point_key] = preparation_id
        self._reserved_by_preparation.setdefault(preparation_id, set()).add(point_key)
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

    def _validate_point_batch_expiry(
        self,
        preparation: NetworkPointBatch,
        expires_at: datetime,
    ) -> None:
        """Validate one point-only deadline against its publication fence."""

        with self._lock:
            capability = self._active_open_point_batch_locked(preparation)
            deadline_floor = max(
                self._pending_watermark or self._watermark,
                capability.linearization_time,
            )
            if expires_at <= deadline_floor:
                raise StateError("Network runtime point expiry must follow the batch linearization")
            if expires_at != _MAX_TIME and expires_at > self._window_end:
                raise StateError("Network runtime point expiry exceeds the runtime window")

    def _seal_point_batch(self, preparation: NetworkPointBatch) -> NetworkPointBatchToken:
        """Freeze one point-only overlay and retain its exact capability."""

        if type(preparation._expectations) is not dict or type(preparation._mutations) is not dict:
            raise StateError("Network point batch contains a malformed overlay map")
        canonical_expectations: dict[_PointKey, _PointExpectation] = {}
        for public_key, value in preparation._expectations.items():
            expectation = _canonical_expectation(value)
            canonical_key = _canonical_point_key(public_key)
            if canonical_key != (expectation.family, expectation.key):
                raise StateError("Network point-batch expectation key disagrees with its payload")
            if canonical_key in canonical_expectations:
                raise StateError("Network point batch contains duplicate expectations")
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
                raise StateError("Network point-batch mutation key disagrees with its payload")
            if canonical_key in canonical_mutations:
                raise StateError("Network point batch contains duplicate mutations")
            if canonical_key not in canonical_expectations:
                raise StateError("Network point-batch mutation has no reserved expectation")
            canonical_mutations[canonical_key] = mutation
        mutations = tuple(
            canonical_mutations[key] for key in sorted(canonical_mutations, key=_point_key_order)
        )
        if not mutations:
            raise StateError("Network point batch must publish at least one mutation")
        with self._lock:
            open_capability = self._active_open_point_batch_locked(preparation)
            overlay_digest = hashlib.sha256(
                f"point:{open_capability.preparation_id}:{open_capability.stable_id}".encode()
            ).hexdigest()
            fence = self._pending_watermark or self._watermark
            if open_capability.linearization_time < fence:
                raise StateError("Network point batch starts behind the runtime watermark")
            deadline_floor = max(fence, open_capability.linearization_time)
            if any(mutation.expires_at <= deadline_floor for mutation in mutations):
                raise StateError("Network point expiry was overtaken before batch seal")
            self._validate_expectations_locked(expectations)
            reserved_points = tuple(
                (expectation.family, expectation.key) for expectation in expectations
            )
            self._validate_point_batch_reservations_locked(
                open_capability.preparation_id,
                reserved_points,
            )
            token = NetworkPointBatchToken(
                preparation_id=open_capability.preparation_id,
                stable_id=open_capability.stable_id,
                linearization_time=open_capability.linearization_time,
                overlay_digest=overlay_digest,
                point_mutations=len(mutations),
                _runtime_token=id(self),
            )
            token = replace(
                token,
                _integrity_token=_point_batch_token_integrity(self._secret, token),
            )
            capability = _PreparedPointBatchCapability(
                token_identity=id(token),
                preparation_id=open_capability.preparation_id,
                integrity_token=token.publication_token,
                trusted_token=token,
                expectations=expectations,
                mutations=mutations,
                reserved_points=reserved_points,
            )
            self._open_point_batches.pop(open_capability.preparation_id)
            self._open_point_batch_objects.pop(id(preparation))
            self._open_point_batch_capabilities_by_identity.pop(id(preparation))
            self._point_batch_tokens[open_capability.preparation_id] = token
            self._point_batch_capabilities[id(token)] = capability
            self._preparation_fences.set(
                open_capability.preparation_id,
                open_capability.linearization_time,
            )
            return token

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
        with self._lock:
            open_capability = self._active_open_preparation_locked(preparation)
            transport_record = self._transport_records_by_preparation.get(
                open_capability.preparation_id
            )
            adopted_transport_id = self._adopted_transport_by_preparation.get(
                open_capability.preparation_id,
                "",
            )
            transport_occurrence_id = (
                transport_record.lease.occurrence_stable_id
                if transport_record is not None
                else adopted_transport_id
            )
            retained_transport_record = transport_record
            if retained_transport_record is None and adopted_transport_id:
                retained_transport_record = self._transport_records_by_occurrence.get(
                    adopted_transport_id
                )
        overlay_digest = hashlib.sha256(
            f"network:{open_capability.preparation_id}:{open_capability.stable_id}".encode()
        ).hexdigest()
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
        if retained_transport_record is not None:
            lease = retained_transport_record.lease
            transaction_tuple = (
                _canonical_ip(transaction.src_ip, field_name="transaction source IP"),
                transaction.src_port,
                _canonical_ip(transaction.dst_ip, field_name="transaction destination IP"),
                transaction.dst_port,
                transaction.protocol.casefold(),
            )
            if (
                transaction.stable_id != lease.occurrence_stable_id
                or transaction_tuple != lease.tuple_key
                or transaction_start != lease.opened_at
                or transaction.closed_at != lease.closed_at
            ):
                raise StateError("Final network transaction disagrees with its transport lease")
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
            transport_occurrence_id=transport_occurrence_id,
            _runtime_token=id(self),
        )
        token = replace(token, _integrity_token=_token_integrity(self._secret, token))
        public_result = trusted_result
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
            capability = _PreparedCapability(
                token_identity=id(token),
                preparation_id=open_capability.preparation_id,
                integrity_token=token.publication_token,
                trusted_token=token,
                trusted_root=root,
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

    def _cancel_open_point_batch(self, preparation: NetworkPointBatch) -> None:
        with self._lock:
            capability = self._active_open_point_batch_locked(preparation)
            self._open_point_batches.pop(capability.preparation_id)
            self._open_point_batch_objects.pop(id(preparation))
            self._open_point_batch_capabilities_by_identity.pop(id(preparation))
            self._preparation_fences.remove(capability.preparation_id)
            self._release_point_reservations_locked(capability.preparation_id)

    def _active_open_point_batch_locked(
        self,
        preparation: NetworkPointBatch,
    ) -> _OpenPointBatchCapability:
        capability = self._open_point_batch_capabilities_by_identity.get(id(preparation))
        if (
            capability is None
            or capability.preparation_identity != id(preparation)
            or self._open_point_batches.get(capability.preparation_id) is not capability
            or self._open_point_batch_objects.get(id(preparation)) is not preparation
        ):
            raise StateError("Network point batch is stale or foreign")
        return capability

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
            self._release_transport_preparation_locked(capability.preparation_id)

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

    def _bind_transaction_identity(
        self,
        preparation: NetworkTransactionPreparation,
        stable_id: str,
    ) -> None:
        """Atomically replace one provisional preparation ID with its final ID."""

        if type(stable_id) is not str or not stable_id.strip():
            raise ValueError("Final network transaction stable_id must not be empty")
        with self._lock:
            capability = self._active_open_preparation_locked(preparation)
            if preparation._stable_id != capability.stable_id:
                raise StateError("Network transaction preparation identity is inconsistent")
            if capability.identity_bound:
                raise StateError("Network transaction preparation identity is already finalized")
            rebound = replace(capability, stable_id=stable_id, identity_bound=True)
            preparation._stable_id = stable_id
            self._open_preparations[capability.preparation_id] = rebound
            self._open_capabilities_by_identity[id(preparation)] = rebound

    def _active_point_batch_capability_locked(
        self,
        token: NetworkPointBatchToken,
    ) -> _PreparedPointBatchCapability:
        if type(token) is not NetworkPointBatchToken:
            raise StateError("Network point-batch token has an invalid type")
        capability = self._point_batch_capabilities.get(id(token))
        if capability is None:
            if type(token._runtime_token) is not int or token._runtime_token != id(self):
                raise StateError("Network point-batch token belongs to another runtime")
            raise StateError("Network point-batch token is stale or already consumed")
        active = self._point_batch_tokens.get(capability.preparation_id)
        if active is not token:
            raise StateError("Network point-batch token is stale or already consumed")
        return capability

    def _claim_point_batch(
        self,
        token: NetworkPointBatchToken,
    ) -> _PreparedPointBatchCapability:
        if type(token) is not NetworkPointBatchToken:
            raise StateError("Network point-batch token has an invalid type")
        error: StateError | None = None
        with self._lock:
            capability = self._point_batch_capabilities.get(id(token))
            if capability is not None and capability.preparation_id in self._claimed_point_batches:
                raise StateError("Network point-batch token is already claimed")
            try:
                capability = self._active_point_batch_capability_locked(token)
                fence = self._pending_watermark or self._watermark
                publication_floor = max(
                    fence,
                    capability.trusted_token.linearization_time,
                )
                if capability.trusted_token.linearization_time < fence:
                    raise StateError("Network point-batch token starts behind the watermark")
                if any(
                    mutation.expires_at <= publication_floor for mutation in capability.mutations
                ):
                    raise StateError("Network point expiry was overtaken before batch claim")
                self._validate_expectations_locked(capability.expectations)
                self._validate_point_batch_reservations_locked(
                    capability.preparation_id,
                    capability.reserved_points,
                )
                self._claimed_point_batches.add(capability.preparation_id)
            except StateError as exc:
                if capability is not None:
                    self._release_point_batch_capability_locked(capability)
                error = exc
        if error is not None:
            raise error
        assert capability is not None
        return capability

    def _register_claimed_point_batch(
        self,
        prepared: NetworkPointBatchPreparedCommit,
        *,
        capability: _PreparedPointBatchCapability,
        token: NetworkPointBatchToken,
    ) -> None:
        with self._lock:
            if capability.preparation_id not in self._claimed_point_batches:
                raise StateError("Network point-batch token is not claimed")
            if self._point_batch_capabilities.get(id(token)) is not capability:
                raise StateError("Network point-batch claim capability changed")
            self._claimed_point_batch_commits[id(prepared)] = _ClaimedPointBatchCapability(
                prepared_identity=id(prepared),
                preparation_id=capability.preparation_id,
                token=token,
                claim_thread_id=get_ident(),
            )

    def _close_claimed_point_batch(self, prepared: NetworkPointBatchPreparedCommit) -> None:
        with self._lock:
            capability = self._claimed_point_batch_commits.pop(id(prepared), None)
            if capability is not None and capability.prepared_identity != id(prepared):
                raise StateError("Network point-batch claim identity diverged")

    def _cancel_claimed_point_batch(self, token: NetworkPointBatchToken) -> None:
        with self._lock:
            capability = self._point_batch_capabilities.get(id(token))
            if capability is None:
                return
            if capability.preparation_id not in self._claimed_point_batches:
                return
            self._release_point_batch_capability_locked(capability)

    def _commit_point_batch_claim_no_fail(
        self,
        prepared: NetworkPointBatchPreparedCommit,
    ) -> NetworkPointBatchReceipt:
        with self._lock:
            composite = self._claimed_point_batch_commits.get(id(prepared))
            if composite is None or composite.prepared_identity != id(prepared):
                raise StateError("Network point-batch claim is stale or foreign")
            if composite.claim_thread_id != get_ident():
                raise StateError("Network point batch must commit on its claiming thread")
            capability = self._point_batch_capabilities.get(id(composite.token))
            if (
                capability is None
                or capability.preparation_id != composite.preparation_id
                or capability.preparation_id not in self._claimed_point_batches
            ):
                raise StateError("Network point-batch claim lost its authority")

            # Claim validation and exact-key reservations make the remainder
            # primitive and structurally no-fail. Caller-owned token fields are
            # never revisited after this point.
            trusted_token = capability.trusted_token
            tombstone_anchor = max(
                self._watermark,
                trusted_token.linearization_time,
            )
            for mutation in capability.mutations:
                self._apply_point_mutation_locked(
                    mutation,
                    tombstone_anchor=tombstone_anchor,
                    trusted_value=True,
                )
            receipt = NetworkPointBatchReceipt(
                publication_token=capability.integrity_token,
                stable_id=trusted_token.stable_id,
                overlay_digest=trusted_token.overlay_digest,
                committed_runtime_digest=self._state_digest_locked(),
                committed_point_mutations=len(capability.mutations),
                _runtime_token=id(self),
            )
            receipt = replace(
                receipt,
                _integrity_token=_point_batch_receipt_integrity(self._secret, receipt),
            )
            self._release_point_batch_claim_no_fail_locked(capability)
            return receipt

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
            self._commit_transport_preparation_locked(capability.preparation_id)
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

    def _validate_point_batch_reservations_locked(
        self,
        preparation_id: int,
        reserved_points: tuple[_PointKey, ...],
    ) -> None:
        expected = set(reserved_points)
        retained = self._reserved_by_preparation.get(preparation_id, set())
        if retained != expected or any(
            self._reserved_points.get(point_key) != preparation_id for point_key in expected
        ):
            raise StateError("Network point-batch reservations changed after preparation")

    def _release_point_batch_capability_locked(
        self,
        capability: _PreparedPointBatchCapability,
    ) -> None:
        active = self._point_batch_tokens.get(capability.preparation_id)
        retained = self._point_batch_capabilities.get(capability.token_identity)
        if active is None or id(active) != capability.token_identity or retained is not capability:
            raise StateError("Network point-batch capability ownership diverged")
        self._point_batch_tokens.pop(capability.preparation_id)
        self._point_batch_capabilities.pop(capability.token_identity)
        self._claimed_point_batches.discard(capability.preparation_id)
        self._preparation_fences.remove(capability.preparation_id)
        self._release_point_reservations_locked(capability.preparation_id)

    def _release_point_batch_claim_no_fail_locked(
        self,
        capability: _PreparedPointBatchCapability,
    ) -> None:
        """Release a claim whose exact ownership was validated before publication."""

        self._point_batch_tokens.pop(capability.preparation_id, None)
        self._point_batch_capabilities.pop(capability.token_identity, None)
        self._claimed_point_batches.discard(capability.preparation_id)
        self._preparation_fences.remove(capability.preparation_id)
        self._release_point_reservations_locked(capability.preparation_id)

    def _release_capability_locked(self, capability: _PreparedCapability) -> None:
        active = self._prepared_tokens.pop(capability.preparation_id, None)
        retained = self._prepared_capabilities.pop(capability.token_identity, None)
        self._claimed_preparations.discard(capability.preparation_id)
        self._preparation_fences.remove(capability.preparation_id)
        self._release_point_reservations_locked(capability.preparation_id)
        self._release_transport_preparation_locked(capability.preparation_id)
        if active is None or id(active) != capability.token_identity or retained is not capability:
            raise StateError("Network transaction capability ownership diverged")

    def _commit_transport_preparation_locked(self, preparation_id: int) -> None:
        """Publish one pending lease and its 24-hour freshness timestamp."""

        record = self._transport_records_by_preparation.get(preparation_id)
        if record is None:
            return
        if record.committed:
            raise StateError("Transport lease was already committed")
        committed = replace(record, committed=True)
        lease = committed.lease
        bucket = self._transport_buckets.get(lease.tuple_key)
        if bucket is None and lease.opened_at != lease.closed_at:
            raise StateError("Pending transport lease lost its interval bucket")
        if bucket is not None:
            for index, candidate in enumerate(bucket):
                if candidate is record:
                    bucket[index] = committed
                    break
            else:
                raise StateError("Pending transport lease lost its bucket record")
        self._transport_records_by_occurrence[lease.occurrence_stable_id] = committed
        self._transport_records_by_preparation[preparation_id] = committed
        self._pending_transport_leases -= 1
        self._transport_candidate_inspections += committed.candidate_inspections
        if committed.adaptive_reuse:
            self._adaptive_transport_reuses += 1
        committed_bucket_occupancy = sum(1 for candidate in bucket or () if candidate.committed)
        self._peak_transport_bucket_occupancy = max(
            self._peak_transport_bucket_occupancy,
            committed_bucket_occupancy,
        )
        ordinal = self._next_transport_ordinal
        self._next_transport_ordinal += 1
        self._transport_lease_deadlines.replace(
            lease.occurrence_stable_id,
            (lease.closed_at, ordinal, lease.occurrence_stable_id),
        )
        prior_freshness = self._transport_freshness.get(lease.tuple_key)
        freshness_component = 0
        if prior_freshness is not None:
            freshness_component = self._state_component(
                "network-transport-freshness-v1",
                (lease.tuple_key, prior_freshness),
            )
        seen_at = max(lease.closed_at, prior_freshness or lease.closed_at)
        self._transport_freshness[lease.tuple_key] = seen_at
        freshness_expiry = (
            self._window_end
            if seen_at > _MAX_TIME - _TRANSPORT_FRESHNESS_RETENTION
            else min(self._window_end, seen_at + _TRANSPORT_FRESHNESS_RETENTION)
        )
        self._transport_freshness_deadlines.replace(
            lease.tuple_key,
            (freshness_expiry, ordinal, lease.tuple_key),
        )
        self._transport_state_xor ^= freshness_component
        self._transport_state_xor ^= self._state_component(
            "network-transport-freshness-v1",
            (lease.tuple_key, seen_at),
        )
        self._transport_state_xor ^= self._state_component(
            "network-transport-lease-v1",
            _transport_lease_digest_value(lease),
        )
        self._live_transport_leases += 1

    def _release_transport_preparation_locked(self, preparation_id: int) -> None:
        """Release pending ownership, retaining an already committed lease."""

        self._adopted_transport_by_preparation.pop(preparation_id, None)
        record = self._transport_records_by_preparation.pop(preparation_id, None)
        if record is None or record.committed:
            return
        self._pending_transport_leases -= 1
        self._remove_transport_record_locked(record)

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
            "network-runtime-state-v3",
            self._window_start,
            self._window_end,
            self._tombstone_retention,
            self._watermark,
            self._pending_watermark,
            self._point_state_xor,
            self._live_points,
            self._tombstone_points,
            len(self._expiry_heap),
            self._transport_state_xor,
            self._live_transport_leases,
            len(self._transport_freshness),
        )
        return hashlib.sha256(repr(_freeze_digest_value(state)).encode()).hexdigest()


__all__ = [
    "NetworkConnectionCommitResult",
    "NetworkCryptographicMaterialPreparation",
    "NetworkPointBatch",
    "NetworkPointBatchPreparedCommit",
    "NetworkPointBatchReceipt",
    "NetworkPointBatchToken",
    "NetworkRuntimePointFamily",
    "NetworkRuntimeWatermarkPage",
    "NetworkTransactionPreparation",
    "NetworkTransactionPreparationReceipt",
    "NetworkTransactionPreparationToken",
    "NetworkTransactionPreparedCommit",
    "NetworkTransactionRuntime",
    "NetworkTransactionRuntimeCensus",
    "NetworkTransportLease",
    "NetworkTransportLifecycleMode",
    "PreparedNetworkTransactionRoot",
]

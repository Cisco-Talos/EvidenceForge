# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""HTTP protocol manager for duration-stable persistent application channels.

The network planner owns transport construction and source-native rendering.
This module owns only the compact state required to decide whether a later HTTP
transaction can reuse that already-planned transport.  Completed operations are
collapsed into counters by :class:`ApplicationChannelRegistry`; no rendered
records, payload bytes, or duration-wide transaction history are retained.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from threading import Condition, Lock, RLock
from typing import Literal
from weakref import WeakValueDictionary

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelCensus,
    ApplicationChannelIdentity,
    ApplicationChannelSnapshot,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.generation.application_channels import (
    ApplicationChannelAdmissionReceipt,
    ApplicationChannelAdmissionResult,
    ApplicationChannelAdmissionToken,
    ApplicationChannelPreparedCommit,
    ApplicationChannelRegistry,
)
from evidenceforge.generation.indexes import (
    IndexMetrics,
    PackedByteRowStore,
    PackedHandleExpiryIndex,
    PackedUniqueDigestMap,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc

_DEFAULT_REUSE_GUARD = timedelta(milliseconds=900)
_DEFAULT_CLOSED_GRACE = timedelta(seconds=30)
_DEFAULT_OPERATION_BUDGET = 65_535
_TRANSACTION_GAP = timedelta(microseconds=1)
_PRIMARY_COMPACTION_WORK_PER_WATERMARK = 4_096
_EMPTY_PRIMARY_MAP_BYTES = 512
_ESTIMATED_PRIMARY_HASH_ENTRY_BYTES = 32
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_HTTP_TRANSPORT_HEADER = struct.Struct("<I3q5H")
_HTTP_TRANSPORT_TEXT_FIELDS = 5
_DECODED_CACHE_CAPACITY_PER_SHARD = 256


def _required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _semantic_digest(namespace: str, values: tuple[str | int, ...]) -> str:
    """Return a stable collision-resistant digest for canonical primitive fields."""

    encoded = repr((namespace, *values)).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _datetime_to_microseconds(value: datetime) -> int:
    delta = ensure_utc(value) - _EPOCH
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000) + delta.microseconds


def _datetime_from_microseconds(value: int) -> datetime:
    return _EPOCH + timedelta(microseconds=value)


@dataclass(frozen=True, slots=True)
class HttpChannelAffinity:
    """Exact affinity for one reusable HTTP or HTTPS transport.

    The planner keys reuse by source IP, destination tuple, transport security,
    HTTP Host, and User-Agent. Keeping transport security explicit prevents a
    cleartext request from ever reusing a TLS parent on a nonstandard port.
    The digest gives the common registry one compact exact key.
    """

    src_ip: str
    dst_ip: str
    dst_port: int
    host: str
    user_agent: str
    transport_security: str = "cleartext"

    def __post_init__(self) -> None:
        """Validate and normalize fields exactly once at the boundary."""

        object.__setattr__(self, "src_ip", _required_text(self.src_ip, "src_ip"))
        object.__setattr__(self, "dst_ip", _required_text(self.dst_ip, "dst_ip"))
        if self.dst_port <= 0 or self.dst_port > 65_535:
            raise ValueError("HTTP channel dst_port must be between 1 and 65535")
        normalized_host = _required_text(self.host, "host").lower().rstrip(".")
        if not normalized_host:
            raise ValueError("HTTP channel host must not contain only dots")
        object.__setattr__(self, "host", normalized_host)
        object.__setattr__(self, "user_agent", self.user_agent.lower())
        transport_security = self.transport_security.strip().casefold()
        if transport_security not in {"cleartext", "tls"}:
            raise ValueError("HTTP channel transport_security must be 'cleartext' or 'tls'")
        object.__setattr__(self, "transport_security", transport_security)

    @classmethod
    def from_request(
        cls,
        *,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        http_host: str,
        resolved_hostname: str = "",
        user_agent: str = "",
        transport_security: str = "cleartext",
    ) -> HttpChannelAffinity:
        """Build the exact affinity used by the pre-migration HTTP cache."""

        return cls(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            host=http_host or resolved_hostname or dst_ip,
            user_agent=user_agent,
            transport_security=transport_security,
        )

    @property
    def digest(self) -> str:
        """Return the stable common-registry affinity key."""

        return _semantic_digest(
            "http-channel-affinity-v2",
            (
                self.src_ip,
                self.dst_ip,
                self.dst_port,
                self.host,
                self.user_agent,
                self.transport_security,
            ),
        )

    @property
    def owner_id(self) -> str:
        """Return the legacy-compatible source owner partition."""

        return f"http-source:{self.src_ip}"


@dataclass(frozen=True, slots=True)
class HttpChannelTransport:
    """Immutable HTTP-specific view of one reusable canonical transport."""

    channel_id: str
    affinity_digest: str
    transport_id: str
    zeek_uid: str
    conn_id: str
    src_port: int
    opened_at: datetime
    closes_at: datetime
    reuse_deadline: datetime

    def __post_init__(self) -> None:
        """Normalize the interval and reject incomplete wire identities."""

        for field_name in (
            "channel_id",
            "affinity_digest",
            "transport_id",
            "zeek_uid",
            "conn_id",
        ):
            object.__setattr__(
                self,
                field_name,
                _required_text(getattr(self, field_name), field_name),
            )
        if self.src_port <= 0 or self.src_port > 65_535:
            raise ValueError("HTTP channel src_port must be between 1 and 65535")
        opened_at = ensure_utc(self.opened_at)
        closes_at = ensure_utc(self.closes_at)
        reuse_deadline = ensure_utc(self.reuse_deadline)
        if closes_at <= opened_at:
            raise ValueError("HTTP transport close must follow its open")
        if reuse_deadline <= opened_at or reuse_deadline > closes_at:
            raise ValueError("HTTP reuse deadline must be inside its transport interval")
        object.__setattr__(self, "opened_at", opened_at)
        object.__setattr__(self, "closes_at", closes_at)
        object.__setattr__(self, "reuse_deadline", reuse_deadline)


@dataclass(frozen=True, slots=True)
class HttpChannelReuse:
    """Frozen identities and timing returned for one accepted HTTP reuse."""

    channel_id: str
    operation_id: str
    zeek_uid: str
    conn_id: str
    src_port: int
    trans_depth: int
    canonical_request_time: datetime

    def __post_init__(self) -> None:
        """Normalize the returned request time."""

        object.__setattr__(
            self,
            "canonical_request_time",
            ensure_utc(self.canonical_request_time),
        )


@dataclass(frozen=True, slots=True)
class HttpChannelAdmissionToken:
    """Opaque manager reservation for one coupled HTTP/common-channel mutation."""

    kind: Literal["open_transport", "reuse"]
    application_token: ApplicationChannelAdmissionToken = field(repr=False)
    result: HttpChannelTransport | HttpChannelReuse
    expected_transport: HttpChannelTransport | None = field(repr=False, default=None)
    prepared_transport: HttpChannelTransport | None = field(repr=False, default=None)
    _manager_token: int = field(repr=False, default=0)
    _reservation_id: int = field(repr=False, default=0)
    _owner_id: str = field(repr=False, default="")
    _owner_shard_id: int = field(repr=False, default=0)
    _reserved_channel_ids: tuple[str, ...] = field(repr=False, default=())
    _reserved_affinity_digests: tuple[str, ...] = field(repr=False, default=())
    _integrity_token: str = field(repr=False, default="")

    @property
    def linearization_time(self) -> datetime:
        """Return the canonical frontier protected while this token is claimed."""

        return self.application_token.linearization_time

    @property
    def publication_token(self) -> str:
        """Return the stable opaque manager capability binding."""

        return self._integrity_token


def _http_admission_integrity_token(
    authority_secret: bytes,
    token: HttpChannelAdmissionToken,
) -> str:
    """Return a compact owner-issued HTTP capability label."""

    del authority_secret
    return hashlib.sha256(
        f"http-admission:{token._manager_token}:{token._reservation_id}".encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class _HttpAdmissionCapability:
    """Manager-owned immutable locator and trusted HTTP admission preimage."""

    token_id: int
    reservation_id: int
    integrity_token: str
    application_token: ApplicationChannelAdmissionToken
    trusted_token: HttpChannelAdmissionToken
    owner_id: str
    owner_shard_id: int
    reserved_channel_ids: tuple[str, ...]
    reserved_affinity_digests: tuple[str, ...]
    linearization_time: datetime


@dataclass(frozen=True, slots=True, weakref_slot=True)
class HttpChannelAdmissionReceipt:
    """Authenticated proof of one committed HTTP/common-channel admission."""

    manager_kind: Literal["http"]
    manager_id: str
    kind: Literal["open_transport", "reuse"]
    publication_token: str
    application_receipt: ApplicationChannelAdmissionReceipt
    application_receipt_token: str
    channel_id: str
    operation_id: str
    transport_id: str
    sidecar_result: HttpChannelTransport | HttpChannelReuse
    sidecar_result_digest: str
    _manager_token: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")

    @property
    def receipt_token(self) -> str:
        """Return the opaque keyed proof over the complete manager result."""

        return self._integrity_token


def http_channel_sidecar_result_digest(
    result: HttpChannelTransport | HttpChannelReuse,
) -> str:
    """Return a stable digest of one exact frozen HTTP sidecar result."""

    if isinstance(result, HttpChannelTransport):
        semantic_result: tuple[object, ...] = (
            "transport",
            result.channel_id,
            result.affinity_digest,
            result.transport_id,
            result.zeek_uid,
            result.conn_id,
            result.src_port,
            result.opened_at,
            result.closes_at,
            result.reuse_deadline,
        )
    else:
        semantic_result = (
            "reuse",
            result.channel_id,
            result.operation_id,
            result.zeek_uid,
            result.conn_id,
            result.src_port,
            result.trans_depth,
            result.canonical_request_time,
        )
    return hashlib.sha256(
        repr(("http-channel-sidecar-result-v1", semantic_result)).encode()
    ).hexdigest()


def _http_admission_receipt_integrity_token(
    authority_secret: bytes,
    receipt: HttpChannelAdmissionReceipt,
) -> str:
    """Authenticate exact manager, common receipt, and HTTP result membership."""

    del authority_secret
    return hashlib.sha256(
        f"http-receipt:{receipt._manager_token}:{receipt.publication_token}".encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class HttpChannelAdmissionResult:
    """Frozen HTTP result plus authenticated common and manager proofs."""

    result: HttpChannelTransport | HttpChannelReuse
    application: ApplicationChannelAdmissionResult
    receipt: HttpChannelAdmissionReceipt


class HttpChannelPreparedCommit:
    """No-lock-body capability for one final HTTP/common-channel commit."""

    __slots__ = (
        "_active",
        "_application_commit",
        "_committed",
        "_manager",
        "_result",
        "_token",
    )

    def __init__(
        self,
        manager: HttpApplicationChannelManager,
        token: HttpChannelAdmissionToken,
        application_commit: ApplicationChannelPreparedCommit,
    ) -> None:
        self._manager = manager
        self._token = token
        self._application_commit = application_commit
        self._active = True
        self._committed = False
        self._result: HttpChannelAdmissionResult | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact manager claim has committed."""

        return self._committed

    @property
    def result(self) -> HttpChannelAdmissionResult | None:
        """Return the frozen HTTP result after commit."""

        return self._result

    def commit_no_fail(self) -> HttpChannelAdmissionResult:
        """Publish the fully claimed common admission and HTTP sidecar mutation."""

        if not self._active:
            raise StateError("HTTP channel prepared commit is no longer active")
        if self._committed:
            raise StateError("HTTP channel prepared admission was already committed")
        self._result = self._manager._commit_claimed_admission(
            self._token,
            self._application_commit,
        )
        self._committed = True
        return self._result

    def commit(self) -> HttpChannelAdmissionResult:
        """Compatibility alias for :meth:`commit_no_fail`."""

        return self.commit_no_fail()

    def _close(self) -> None:
        self._active = False


@dataclass(frozen=True, slots=True)
class HttpChannelCensus:
    """Low-cost state and amplification metrics for the HTTP manager."""

    open_transport_views: int
    transport_expiry_entries: int
    stale_transport_expiry_entries: int
    shard_count: int
    max_shard_load: int
    estimated_bytes: int
    sidecar_estimated_index_bytes: int
    decoded_cache_entries: int
    decoded_cache_capacity: int
    decoded_cache_estimated_bytes: int
    lookup_candidates_inspected: int
    sidecar_lookup_candidates_inspected: int
    transport_primary_map_bytes: int
    transport_primary_map_amplification: float
    transport_primary_compaction_pending: int
    transport_primary_compaction_rotations: int
    transport_primary_compaction_work: int
    transport_primary_compaction_seconds: float
    application: ApplicationChannelCensus


class _HttpMutationGate:
    """Admit disjoint mutations concurrently and fence canonical watermarks."""

    def __init__(self) -> None:
        self._condition = Condition(Lock())
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    @contextmanager
    def mutation(self) -> Iterator[None]:
        """Enter one shared protocol mutation lane."""

        with self._condition:
            while self._writer or self._waiting_writers:
                self._condition.wait()
            self._readers += 1
        try:
            yield
        finally:
            with self._condition:
                self._readers -= 1
                if self._readers == 0:
                    self._condition.notify_all()

    @contextmanager
    def watermark(self) -> Iterator[None]:
        """Fence new mutations while one canonical cutoff commits."""

        with self._condition:
            self._waiting_writers += 1
            try:
                while self._writer or self._readers:
                    self._condition.wait()
                self._writer = True
            finally:
                self._waiting_writers -= 1
        try:
            yield
        finally:
            with self._condition:
                self._writer = False
                self._condition.notify_all()


def _transport_estimated_bytes(transport: HttpChannelTransport) -> int:
    """Return a shallow, length-aware retained-byte estimate for one sidecar."""

    return sum(
        sys.getsizeof(value)
        for value in (
            transport,
            transport.channel_id,
            transport.affinity_digest,
            transport.transport_id,
            transport.zeek_uid,
            transport.conn_id,
            transport.opened_at,
            transport.closes_at,
            transport.reuse_deadline,
        )
    )


class _PackedHttpTransportStore:
    """Packed open-only HTTP rows with exact digest routes and bounded decoding."""

    def __init__(self) -> None:
        self._rows = PackedByteRowStore(inline_slot_bytes=256, chunk_slots=256)
        self._channel_routes = PackedUniqueDigestMap(b"ef-http-channel")
        self._affinity_routes = PackedUniqueDigestMap(b"ef-http-aff")
        self._decoded: dict[int, HttpChannelTransport] = {}
        self._decoded_bytes = 0
        self._compaction_rotations = 0
        self._lookup_candidates_inspected = 0

    def __len__(self) -> int:
        return len(self._rows)

    @staticmethod
    def _pack(transport: HttpChannelTransport) -> bytes:
        encoded = tuple(
            value.encode("utf-8")
            for value in (
                transport.channel_id,
                transport.affinity_digest,
                transport.transport_id,
                transport.zeek_uid,
                transport.conn_id,
            )
        )
        lengths = tuple(len(value) for value in encoded)
        if any(length >= 1 << 16 for length in lengths):
            raise ValueError("HTTP packed transport text fields must be shorter than 65,536 bytes")
        return _HTTP_TRANSPORT_HEADER.pack(
            transport.src_port,
            _datetime_to_microseconds(transport.opened_at),
            _datetime_to_microseconds(transport.closes_at),
            _datetime_to_microseconds(transport.reuse_deadline),
            *lengths,
        ) + b"".join(encoded)

    @staticmethod
    def _unpack(row: bytes | memoryview) -> HttpChannelTransport:
        values = _HTTP_TRANSPORT_HEADER.unpack_from(row)
        src_port, opened_us, closes_us, reuse_us = values[:4]
        lengths = values[4 : 4 + _HTTP_TRANSPORT_TEXT_FIELDS]
        offset = _HTTP_TRANSPORT_HEADER.size
        texts: list[str] = []
        for length in lengths:
            segment = row[offset : offset + length]
            texts.append(bytes(segment).decode("utf-8"))
            offset += length
        transport = object.__new__(HttpChannelTransport)
        for name, value in zip(
            ("channel_id", "affinity_digest", "transport_id", "zeek_uid", "conn_id"),
            texts,
            strict=True,
        ):
            object.__setattr__(transport, name, value)
        object.__setattr__(transport, "src_port", src_port)
        object.__setattr__(transport, "opened_at", _datetime_from_microseconds(opened_us))
        object.__setattr__(transport, "closes_at", _datetime_from_microseconds(closes_us))
        object.__setattr__(transport, "reuse_deadline", _datetime_from_microseconds(reuse_us))
        return transport

    def _decode(self, handle: int) -> HttpChannelTransport:
        cached = self._decoded.get(handle)
        if cached is not None:
            return cached
        transport = self._unpack(self._rows.get_by_handle(handle))
        if len(self._decoded) >= _DECODED_CACHE_CAPACITY_PER_SHARD:
            oldest = next(iter(self._decoded))
            evicted = self._decoded.pop(oldest)
            self._decoded_bytes -= _transport_estimated_bytes(evicted)
        self._decoded[handle] = transport
        self._decoded_bytes += _transport_estimated_bytes(transport)
        return transport

    def _decode_uncached(self, handle: int) -> HttpChannelTransport:
        """Decode one row without changing lookup counters or the hot cache."""

        return self._unpack(self._rows.get_by_handle(handle))

    @staticmethod
    def _verify(value: str, expected: str, route_name: str) -> None:
        if value != expected:
            raise StateError(f"HTTP packed {route_name} digest collision")

    def get(self, channel_id: str) -> HttpChannelTransport | None:
        handle = self._channel_routes.get(channel_id)
        if handle is None:
            return None
        self._lookup_candidates_inspected += 1
        transport = self._decode(handle)
        self._verify(transport.channel_id, channel_id, "channel route")
        return transport

    def find_affinity(self, affinity_digest: str) -> HttpChannelTransport | None:
        handle = self._affinity_routes.get(affinity_digest)
        if handle is None:
            return None
        self._lookup_candidates_inspected += 1
        transport = self._decode(handle)
        self._verify(transport.affinity_digest, affinity_digest, "affinity route")
        return transport

    def peek(self, channel_id: str) -> HttpChannelTransport | None:
        """Read one exact row without mutating diagnostic lookup state."""

        handle = self._channel_routes.get(channel_id)
        if handle is None:
            return None
        transport = self._decode_uncached(handle)
        self._verify(transport.channel_id, channel_id, "channel route")
        return transport

    def peek_affinity(self, affinity_digest: str) -> HttpChannelTransport | None:
        """Read one affinity row without mutating diagnostic lookup state."""

        handle = self._affinity_routes.get(affinity_digest)
        if handle is None:
            return None
        transport = self._decode_uncached(handle)
        self._verify(transport.affinity_digest, affinity_digest, "affinity route")
        return transport

    def get_by_handle(self, handle: int) -> HttpChannelTransport:
        return self._decode(handle)

    def handle_for(self, channel_id: str) -> int:
        handle = self._channel_routes.get(channel_id)
        if handle is None:
            raise KeyError(channel_id)
        self._lookup_candidates_inspected += 1
        transport = self._decode(handle)
        self._verify(transport.channel_id, channel_id, "channel route")
        return handle

    def insert(self, transport: HttpChannelTransport) -> int:
        channel_digest = self._channel_routes.digest(transport.channel_id)
        affinity_digest = self._affinity_routes.digest(transport.affinity_digest)
        existing_handle = self._channel_routes.get_digest(channel_digest)
        if existing_handle is not None:
            retained = self._decode(existing_handle)
            self._verify(retained.channel_id, transport.channel_id, "channel route")
            self.delete(transport.channel_id)
        affinity_handle = self._affinity_routes.get_digest(affinity_digest)
        if affinity_handle is not None:
            retained = self._decode(affinity_handle)
            self._verify(retained.affinity_digest, transport.affinity_digest, "affinity route")
            raise StateError("Duplicate HTTP packed affinity route")
        row = self._pack(transport)
        handle = self._rows.insert(row)
        self._channel_routes.set_digest(channel_digest, handle)
        self._affinity_routes.set_digest(affinity_digest, handle)
        return handle

    def delete(self, channel_id: str) -> HttpChannelTransport | None:
        handle = self._channel_routes.get(channel_id)
        if handle is None:
            return None
        self._lookup_candidates_inspected += 1
        transport = self._decode(handle)
        self._verify(transport.channel_id, channel_id, "channel route")
        self._channel_routes.pop(channel_id)
        self._affinity_routes.pop(transport.affinity_digest)
        self._rows.delete(handle)
        cached = self._decoded.pop(handle, None)
        if cached is not None:
            self._decoded_bytes -= _transport_estimated_bytes(cached)
        return transport

    @property
    def estimated_value_bytes(self) -> int:
        return self._rows.estimated_value_bytes + sys.getsizeof(self._decoded) + self._decoded_bytes

    @property
    def decoded_cache_entries(self) -> int:
        return len(self._decoded)

    @property
    def decoded_cache_estimated_bytes(self) -> int:
        return sys.getsizeof(self._decoded) + self._decoded_bytes

    def compact_primary(self, *, max_slots: int = 4_096, force: bool = False) -> int:
        if max_slots < 0:
            raise ValueError("HTTP packed compaction budget cannot be negative")
        forced_empty = force and not len(self)
        for route in (self._channel_routes, self._affinity_routes):
            before = route.metrics().primary_map_backing_bytes
            route.compact_primary(max_entries=max_slots, force=force)
            after = route.metrics().primary_map_backing_bytes
            if after < before:
                self._compaction_rotations += 1
        if forced_empty:
            self._compaction_rotations += 1
        return 0

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        rows = self._rows.metrics(estimate_bytes=estimate_bytes)
        routes = tuple(
            route.metrics(estimate_bytes=estimate_bytes)
            for route in (self._channel_routes, self._affinity_routes)
        )
        return IndexMetrics(
            live_entries=rows.live_entries,
            backing_entries=rows.backing_entries,
            stale_entries=rows.stale_entries,
            allocated_slots=rows.allocated_slots,
            high_water_mark=rows.high_water_mark,
            estimated_bytes=rows.estimated_bytes + sum(item.estimated_bytes for item in routes),
            primary_map_entries=sum(item.primary_map_entries for item in routes),
            primary_map_backing_bytes=sum(item.primary_map_backing_bytes for item in routes),
            primary_compaction_rotations=self._compaction_rotations,
            lookup_candidates_inspected=self._lookup_candidates_inspected,
        )


@dataclass(slots=True)
class _HttpTransportShard:
    """Open-only HTTP sidecars owned by one stable source partition."""

    shard_id: int
    lock: RLock = field(default_factory=RLock)
    transports: _PackedHttpTransportStore = field(default_factory=_PackedHttpTransportStore)
    transport_expiry: PackedHandleExpiryIndex = field(default_factory=PackedHandleExpiryIndex)
    transport_deletions: int = 0

    def primary_metrics(self) -> IndexMetrics:
        """Return public structural metrics for the exact transport map."""

        return self.transports.metrics(estimate_bytes=True)


class HttpApplicationChannelManager:
    """Own exact, bounded HTTP transport reuse on shared application channels."""

    def __init__(
        self,
        *,
        window_start: datetime,
        window_end: datetime,
        registry: ApplicationChannelRegistry | None = None,
        allow_private_registry: bool = False,
        reuse_guard: timedelta = _DEFAULT_REUSE_GUARD,
        closed_grace: timedelta = _DEFAULT_CLOSED_GRACE,
        operation_budget: int = _DEFAULT_OPERATION_BUDGET,
    ) -> None:
        """Create a manager backed by the engine-owned common registry.

        ``allow_private_registry`` is an explicit compatibility escape hatch
        for isolated direct callers. Production managers must receive the one
        engine-owned registry so every protocol shares a canonical watermark.
        """

        if reuse_guard < timedelta(0):
            raise ValueError("HTTP reuse_guard must be non-negative")
        if operation_budget <= 0:
            raise ValueError("HTTP operation_budget must be positive")
        canonical_start = ensure_utc(window_start)
        canonical_end = ensure_utc(window_end)
        if canonical_end < canonical_start:
            raise ValueError("HTTP window_end cannot precede window_start")
        if registry is None:
            if not allow_private_registry:
                raise ValueError(
                    "HTTP manager requires the shared ApplicationChannelRegistry; "
                    "isolated compatibility callers must set allow_private_registry=True"
                )
            registry = ApplicationChannelRegistry(
                window_start=canonical_start,
                window_end=canonical_end,
                closed_grace=closed_grace,
                max_reusable_per_affinity=1,
            )
            self._owns_registry = True
        else:
            if allow_private_registry:
                raise ValueError(
                    "allow_private_registry cannot be combined with an injected registry"
                )
            if registry.window_start != canonical_start or registry.window_end != canonical_end:
                raise ValueError(
                    "HTTP manager window must exactly match the shared application registry"
                )
            self._owns_registry = False
        self._reuse_guard = reuse_guard
        self._operation_budget = operation_budget
        self._registry = registry
        self._shards: dict[int, _HttpTransportShard] = {}
        self._directory_lock = RLock()
        self._gate = _HttpMutationGate()
        self._watermark_lane = Lock()
        self._watermark = canonical_start
        self._compaction_cursor = 0
        self._prepared_lock = RLock()
        self._admission_secret = secrets.token_bytes(32)
        self._manager_id = f"http-manager-{secrets.token_hex(16)}"
        self._next_prepared_reservation_id = 1
        self._prepared_admissions: dict[int, HttpChannelAdmissionToken] = {}
        self._prepared_capabilities: dict[int, _HttpAdmissionCapability] = {}
        self._admission_receipts: WeakValueDictionary[int, HttpChannelAdmissionReceipt] = (
            WeakValueDictionary()
        )
        self._claimed_admissions: set[int] = set()
        self._prepared_channel_ids: dict[str, int] = {}
        self._prepared_affinity_digests: dict[tuple[str, str], int] = {}

    @property
    def application_registry(self) -> ApplicationChannelRegistry:
        """Return the injected common registry for identity/invariant checks."""

        return self._registry

    @property
    def manager_id(self) -> str:
        """Return the stable opaque identity of this manager instance."""

        return self._manager_id

    def authenticates_admission_token(self, token: HttpChannelAdmissionToken) -> bool:
        """Return whether one intact manager/common token pair remains active."""

        if not isinstance(token, HttpChannelAdmissionToken):
            return False
        with self._prepared_lock:
            try:
                capability = self._active_prepared_admission_locked(token)
            except StateError:
                return False
        return self._registry.authenticates_admission_token(capability.application_token)

    def authenticates_admission_receipt(self, receipt: HttpChannelAdmissionReceipt) -> bool:
        """Return whether this manager issued the exact coupled commit receipt."""

        if not isinstance(receipt, HttpChannelAdmissionReceipt):
            return False
        if self._admission_receipts.get(id(receipt)) is not receipt:
            return False
        if not self._registry.authenticates_admission_receipt(receipt.application_receipt):
            return False
        return True

    def _shard(
        self,
        owner_id: str,
        *,
        create: bool,
    ) -> _HttpTransportShard | None:
        shard_id = self._registry.owner_partition_id(owner_id)
        shard = self._shards.get(shard_id)
        if shard is not None or not create:
            return shard
        with self._directory_lock:
            shard = self._shards.get(shard_id)
            if shard is None:
                shard = _HttpTransportShard(shard_id=shard_id)
                self._shards[shard_id] = shard
            return shard

    def owner_partition_id(self, affinity: HttpChannelAffinity) -> int:
        """Return the stable shared owner partition for one exact affinity."""

        return self._registry.owner_partition_id(affinity.owner_id)

    @staticmethod
    def _channel_id(affinity: HttpChannelAffinity | str, transport_id: str) -> str:
        affinity_digest = affinity if isinstance(affinity, str) else affinity.digest
        digest = _semantic_digest(
            "http-channel-v1",
            (affinity_digest, transport_id),
        )
        return f"http-channel-{digest[:32]}"

    @staticmethod
    def _operation_id(channel_id: str, ordinal: int) -> str:
        digest = _semantic_digest("http-operation-v1", (channel_id, ordinal))
        return f"http-operation-{digest[:32]}"

    def _active_prepared_admission_locked(
        self,
        token: HttpChannelAdmissionToken,
    ) -> _HttpAdmissionCapability:
        """Return the manager-owned capability for one intact active token."""

        capability = self._prepared_capabilities.get(id(token))
        if capability is None:
            if token._manager_token != id(self):
                raise StateError("HTTP channel admission token belongs to another manager")
            raise StateError("HTTP channel admission token is stale or already consumed")
        active = self._prepared_admissions.get(capability.reservation_id)
        if active is not token:
            raise StateError("HTTP channel admission token is stale or already consumed")
        if token.application_token is not capability.application_token:
            raise StateError(
                "HTTP channel admission token no longer binds its exact common capability"
            )
        return capability

    def _reject_prepared_conflict_locked(
        self,
        *,
        owner_id: str,
        channel_ids: tuple[str, ...] = (),
        affinity_digests: tuple[str, ...] = (),
    ) -> None:
        """Reject one HTTP mutation crossing a reserved sidecar identity."""

        for channel_id in channel_ids:
            if channel_id and channel_id in self._prepared_channel_ids:
                raise StateError(f"HTTP channel identity {channel_id!r} has a prepared admission")
        for affinity_digest in affinity_digests:
            if (owner_id, affinity_digest) in self._prepared_affinity_digests:
                raise StateError(f"HTTP affinity {affinity_digest!r} has a prepared admission")

    def _register_prepared_admission_locked(
        self,
        token: HttpChannelAdmissionToken,
    ) -> None:
        """Retain only reservation metadata and one trusted immutable preimage."""

        expected = token._integrity_token
        self._reject_prepared_conflict_locked(
            owner_id=token._owner_id,
            channel_ids=token._reserved_channel_ids,
            affinity_digests=token._reserved_affinity_digests,
        )
        capability = _HttpAdmissionCapability(
            token_id=id(token),
            reservation_id=token._reservation_id,
            integrity_token=expected,
            application_token=token.application_token,
            trusted_token=token,
            owner_id=token._owner_id,
            owner_shard_id=token._owner_shard_id,
            reserved_channel_ids=token._reserved_channel_ids,
            reserved_affinity_digests=token._reserved_affinity_digests,
            linearization_time=token.linearization_time,
        )
        self._prepared_admissions[capability.reservation_id] = token
        self._prepared_capabilities[capability.token_id] = capability
        for channel_id in capability.reserved_channel_ids:
            self._prepared_channel_ids[channel_id] = capability.reservation_id
        for affinity_digest in capability.reserved_affinity_digests:
            self._prepared_affinity_digests[(capability.owner_id, affinity_digest)] = (
                capability.reservation_id
            )

    def _release_prepared_capability_locked(
        self,
        capability: _HttpAdmissionCapability,
    ) -> None:
        """Release HTTP reservations using only manager-owned immutable keys."""

        active = self._prepared_admissions.pop(capability.reservation_id, None)
        retained = self._prepared_capabilities.pop(capability.token_id, None)
        if active is None or retained is not capability:
            return
        self._claimed_admissions.discard(capability.reservation_id)
        for channel_id in capability.reserved_channel_ids:
            if self._prepared_channel_ids.get(channel_id) == capability.reservation_id:
                self._prepared_channel_ids.pop(channel_id)
        for affinity_digest in capability.reserved_affinity_digests:
            affinity_key = (capability.owner_id, affinity_digest)
            if self._prepared_affinity_digests.get(affinity_key) == capability.reservation_id:
                self._prepared_affinity_digests.pop(affinity_key)
        if not self._prepared_admissions:
            self._prepared_admissions.clear()
            self._prepared_capabilities.clear()
            self._claimed_admissions.clear()
            self._prepared_channel_ids.clear()
            self._prepared_affinity_digests.clear()

    def _validate_prepared_sidecar_locked(
        self,
        capability: _HttpAdmissionCapability,
    ) -> None:
        """Verify the exact HTTP sidecar preimage without changing lookup state."""

        token = capability.trusted_token
        expected_transport = token.expected_transport
        if token.kind == "open_transport":
            assert isinstance(token.result, HttpChannelTransport)
            affinity_digest = token.result.affinity_digest
        else:
            assert isinstance(token.result, HttpChannelReuse)
            assert expected_transport is not None
            affinity_digest = expected_transport.affinity_digest
        shard = self._shards.get(capability.owner_shard_id)
        current = None
        if shard is not None:
            with shard.lock:
                current = shard.transports.peek_affinity(affinity_digest)
                if token.prepared_transport is not None:
                    occupied = shard.transports.peek(token.prepared_transport.channel_id)
                    if occupied is not None and occupied != expected_transport:
                        raise StateError("prepared HTTP channel identity became occupied")
        if current != expected_transport:
            raise StateError("prepared HTTP transport sidecar changed before commit")

    def open_transport(
        self,
        affinity: HttpChannelAffinity,
        *,
        transport_id: str,
        zeek_uid: str,
        conn_id: str,
        src_port: int,
        opened_at: datetime,
        closes_at: datetime,
        initial_request_time: datetime,
        orig_budget: int,
        resp_budget: int,
        initial_request_body_bytes: int = 0,
        initial_response_body_bytes: int = 0,
        operation_budget: int | None = None,
    ) -> HttpChannelTransport | None:
        """Compatibility wrapper that prepares, claims, and commits one parent."""

        token = self.prepare_open_transport(
            affinity,
            transport_id=transport_id,
            zeek_uid=zeek_uid,
            conn_id=conn_id,
            src_port=src_port,
            opened_at=opened_at,
            closes_at=closes_at,
            initial_request_time=initial_request_time,
            orig_budget=orig_budget,
            resp_budget=resp_budget,
            initial_request_body_bytes=initial_request_body_bytes,
            initial_response_body_bytes=initial_response_body_bytes,
            operation_budget=operation_budget,
        )
        if token is None:
            return None
        with self.prepared_admission(token) as prepared:
            admission = prepared.commit_no_fail()
        result = admission.result
        assert isinstance(result, HttpChannelTransport)
        return result

    def prepare_open_transport(
        self,
        affinity: HttpChannelAffinity,
        *,
        transport_id: str,
        zeek_uid: str,
        conn_id: str,
        src_port: int,
        opened_at: datetime,
        closes_at: datetime,
        initial_request_time: datetime,
        orig_budget: int,
        resp_budget: int,
        initial_request_body_bytes: int = 0,
        initial_response_body_bytes: int = 0,
        operation_budget: int | None = None,
    ) -> HttpChannelAdmissionToken | None:
        """Reserve a parent transport and first operation without publishing them.

        Transports whose close guard leaves no reusable interval are deliberately
        not retained.  This is observably equivalent to the legacy cache, where
        such an entry could never produce a hit, and avoids useless duration-wide
        state.
        """

        normalized_transport_id = _required_text(transport_id, "transport_id")
        normalized_uid = _required_text(zeek_uid, "zeek_uid")
        normalized_conn_id = _required_text(conn_id, "conn_id")
        canonical_open = ensure_utc(opened_at)
        canonical_close = ensure_utc(closes_at)
        request_time = ensure_utc(initial_request_time)
        selected_operation_budget = (
            self._operation_budget if operation_budget is None else operation_budget
        )
        if selected_operation_budget <= 0:
            raise ValueError("HTTP operation budget must be positive")
        if orig_budget < 0 or resp_budget < 0:
            raise ValueError("HTTP channel byte budgets must be non-negative")
        if initial_request_body_bytes < 0 or initial_response_body_bytes < 0:
            raise ValueError("HTTP operation body sizes must be non-negative")
        if initial_request_body_bytes > orig_budget:
            raise StateError("Initial HTTP request body exceeds the transport originator budget")
        if initial_response_body_bytes > resp_budget:
            raise StateError("Initial HTTP response body exceeds the transport responder budget")
        if canonical_close <= canonical_open:
            raise StateError("HTTP transport close must follow its open")
        if request_time < canonical_open or request_time > canonical_close:
            raise StateError("Initial HTTP request time must be inside its transport")

        reuse_deadline = canonical_close - self._reuse_guard
        if reuse_deadline <= canonical_open or request_time >= reuse_deadline:
            return None

        affinity_digest = affinity.digest
        owner_id = affinity.owner_id
        owner_shard_id = self._registry.owner_partition_id(owner_id)
        channel_id = self._channel_id(affinity_digest, normalized_transport_id)
        transport = HttpChannelTransport(
            channel_id=channel_id,
            affinity_digest=affinity_digest,
            transport_id=normalized_transport_id,
            zeek_uid=normalized_uid,
            conn_id=normalized_conn_id,
            src_port=src_port,
            opened_at=canonical_open,
            closes_at=canonical_close,
            reuse_deadline=reuse_deadline,
        )
        # Reject deterministic packed-row failures before the common registry
        # reserves anything. The final insertion can then fail only for an
        # impossible preimage conflict or process-level allocation failure.
        _PackedHttpTransportStore._pack(transport)
        identity = ApplicationChannelIdentity(
            channel_id=channel_id,
            protocol="http",
            owner_id=owner_id,
            affinity_digest=affinity_digest,
            binding=ApplicationTransportBinding(
                transport_id=normalized_transport_id,
                opened_at=canonical_open,
                closes_at=canonical_close,
            ),
            opened_at=canonical_open,
            idle_timeout=canonical_close - canonical_open,
            hard_deadline=canonical_close,
            budget=ApplicationChannelBudget(
                initiator_bytes=orig_budget,
                responder_bytes=resp_budget,
                operations=selected_operation_budget,
            ),
        )
        first_operation = ApplicationOperationReservation(
            operation_id=self._operation_id(channel_id, 0),
            channel_id=channel_id,
            ordinal=0,
            started_at=request_time,
            ended_at=request_time,
            initiator_bytes=initial_request_body_bytes,
            responder_bytes=initial_response_body_bytes,
        )

        with self._gate.mutation(), self._prepared_lock:
            if canonical_open < self._watermark:
                raise StateError("HTTP transports cannot open before the current watermark")
            self._reject_prepared_conflict_locked(
                owner_id=owner_id,
                channel_ids=(channel_id,),
                affinity_digests=(affinity_digest,),
            )
            shard = self._shards.get(owner_shard_id)
            prior = None
            if shard is not None:
                with shard.lock:
                    prior = shard.transports.peek_affinity(affinity_digest)
            reserved_channel_ids = tuple(
                dict.fromkeys(
                    candidate
                    for candidate in (
                        channel_id,
                        prior.channel_id if prior is not None else "",
                    )
                    if candidate
                )
            )
            self._reject_prepared_conflict_locked(
                owner_id=owner_id,
                channel_ids=reserved_channel_ids,
                affinity_digests=(affinity_digest,),
            )

        replacement_channel_id = ""
        replacement_closed_at = None
        replacement_reason = ""
        if prior is not None:
            prior_snapshot = self._registry.get(prior.channel_id)
            if prior_snapshot is not None and prior_snapshot.is_open:
                effective_deadline = min(
                    prior_snapshot.idle_deadline,
                    prior_snapshot.identity.hard_deadline,
                    prior_snapshot.identity.binding.closes_at,
                )
                replacement_channel_id = prior.channel_id
                replacement_closed_at = min(
                    effective_deadline,
                    max(
                        canonical_open,
                        prior_snapshot.identity.opened_at,
                        prior_snapshot.last_activity_at,
                    ),
                )
                replacement_reason = "replaced"
        application_token = self._registry.prepare_open_channel_with_completed_operation(
            identity,
            first_operation,
            replacement_channel_id=replacement_channel_id,
            replacement_closed_at=replacement_closed_at,
            replacement_reason=replacement_reason,
        )
        try:
            with self._gate.mutation(), self._prepared_lock:
                if canonical_open < self._watermark:
                    raise StateError("HTTP transports cannot open before the current watermark")
                self._reject_prepared_conflict_locked(
                    owner_id=owner_id,
                    channel_ids=reserved_channel_ids,
                    affinity_digests=(affinity_digest,),
                )
                current_shard = self._shards.get(owner_shard_id)
                current = None
                if current_shard is not None:
                    with current_shard.lock:
                        current = current_shard.transports.peek_affinity(affinity_digest)
                if current != prior:
                    raise StateError("HTTP transport sidecar changed during preparation")
                reservation_id = self._next_prepared_reservation_id
                self._next_prepared_reservation_id += 1
                token = HttpChannelAdmissionToken(
                    kind="open_transport",
                    application_token=application_token,
                    result=transport,
                    expected_transport=prior,
                    prepared_transport=transport,
                    _manager_token=id(self),
                    _reservation_id=reservation_id,
                    _owner_id=owner_id,
                    _owner_shard_id=owner_shard_id,
                    _reserved_channel_ids=reserved_channel_ids,
                    _reserved_affinity_digests=(affinity_digest,),
                )
                token = replace(
                    token,
                    _integrity_token=_http_admission_integrity_token(
                        self._admission_secret,
                        token,
                    ),
                )
                self._register_prepared_admission_locked(token)
                return token
        except (StateError, ValueError):
            self._registry.cancel_prepared_admission(application_token)
            raise

    def reserve_reuse(
        self,
        affinity: HttpChannelAffinity,
        *,
        requested_at: datetime,
        required_until: datetime | None = None,
        request_body_bytes: int = 0,
        response_body_bytes: int = 0,
    ) -> HttpChannelReuse | None:
        """Compatibility wrapper that commits one prepared reuse immediately."""

        token = self.prepare_reuse(
            affinity,
            requested_at=requested_at,
            required_until=required_until,
            request_body_bytes=request_body_bytes,
            response_body_bytes=response_body_bytes,
        )
        if token is None:
            return None
        with self.prepared_admission(token) as prepared:
            admission = prepared.commit_no_fail()
        result = admission.result
        assert isinstance(result, HttpChannelReuse)
        return result

    def prepare_reuse(
        self,
        affinity: HttpChannelAffinity,
        *,
        requested_at: datetime,
        required_until: datetime | None = None,
        request_body_bytes: int = 0,
        response_body_bytes: int = 0,
    ) -> HttpChannelAdmissionToken | None:
        """Reserve one later transaction without consuming budget or sidecar state.

        Any deadline, span, or capacity miss leaves the existing channel intact.
        A later prepared fresh transport may replace it atomically at commit.
        Equality with the immutable parent close remains admissible.
        """

        if request_body_bytes < 0 or response_body_bytes < 0:
            raise ValueError("HTTP operation body sizes must be non-negative")
        canonical_request = ensure_utc(requested_at)
        canonical_required = (
            canonical_request if required_until is None else ensure_utc(required_until)
        )
        if canonical_required < canonical_request:
            raise ValueError("HTTP required_until must not precede requested_at")
        required_span = canonical_required - canonical_request
        affinity_digest = affinity.digest
        owner_id = affinity.owner_id
        owner_shard_id = self._registry.owner_partition_id(owner_id)
        shard = self._shards.get(owner_shard_id)
        if shard is None:
            return None
        with self._gate.mutation(), self._prepared_lock:
            if canonical_request < self._watermark:
                raise StateError("HTTP reuse cannot start before the current watermark")
            self._reject_prepared_conflict_locked(
                owner_id=owner_id,
                affinity_digests=(affinity_digest,),
            )
            with shard.lock:
                transport = shard.transports.peek_affinity(affinity_digest)
            if transport is None:
                return None
            self._reject_prepared_conflict_locked(
                owner_id=owner_id,
                channel_ids=(transport.channel_id,),
                affinity_digests=(affinity_digest,),
            )
            snapshot = self._registry.get(transport.channel_id)
            if snapshot is None or not snapshot.is_open:
                return None
            ordered_request = max(
                canonical_request,
                snapshot.last_activity_at + _TRANSACTION_GAP,
            )
            if ordered_request >= transport.reuse_deadline:
                return None
            if ordered_request + required_span > transport.closes_at:
                return None
            effective_deadline = min(
                snapshot.idle_deadline,
                snapshot.identity.hard_deadline,
                snapshot.identity.binding.closes_at,
            )
            if (
                snapshot.identity.owner_id != owner_id
                or snapshot.identity.affinity_digest != affinity_digest
                or ordered_request >= effective_deadline
            ):
                return None

            budget = snapshot.identity.budget
            fits = (
                snapshot.reserved_initiator_bytes + request_body_bytes <= budget.initiator_bytes
                and snapshot.reserved_responder_bytes + response_body_bytes
                <= budget.responder_bytes
                and snapshot.reserved_operations + 1 <= budget.operations
            )
            if not fits:
                return None

            ordinal = snapshot.reserved_operations
            operation_id = self._operation_id(snapshot.channel_id, ordinal)
            reservation = ApplicationOperationReservation(
                operation_id=operation_id,
                channel_id=snapshot.channel_id,
                ordinal=ordinal,
                started_at=ordered_request,
                ended_at=ordered_request,
                initiator_bytes=request_body_bytes,
                responder_bytes=response_body_bytes,
            )
            result = HttpChannelReuse(
                channel_id=snapshot.channel_id,
                operation_id=operation_id,
                zeek_uid=transport.zeek_uid,
                conn_id=transport.conn_id,
                src_port=transport.src_port,
                trans_depth=snapshot.reserved_operations + 1,
                canonical_request_time=ordered_request,
            )

        application_token = self._registry.prepare_completed_operation(reservation)
        try:
            with self._gate.mutation(), self._prepared_lock:
                if canonical_request < self._watermark:
                    raise StateError("HTTP reuse cannot start before the current watermark")
                self._reject_prepared_conflict_locked(
                    owner_id=owner_id,
                    channel_ids=(transport.channel_id,),
                    affinity_digests=(affinity_digest,),
                )
                current_shard = self._shards.get(owner_shard_id)
                current = None
                if current_shard is not None:
                    with current_shard.lock:
                        current = current_shard.transports.peek_affinity(affinity_digest)
                if current != transport:
                    raise StateError("HTTP transport sidecar changed during reuse preparation")
                reservation_id = self._next_prepared_reservation_id
                self._next_prepared_reservation_id += 1
                token = HttpChannelAdmissionToken(
                    kind="reuse",
                    application_token=application_token,
                    result=result,
                    expected_transport=transport,
                    _manager_token=id(self),
                    _reservation_id=reservation_id,
                    _owner_id=owner_id,
                    _owner_shard_id=owner_shard_id,
                    _reserved_channel_ids=(transport.channel_id,),
                    _reserved_affinity_digests=(affinity_digest,),
                )
                token = replace(
                    token,
                    _integrity_token=_http_admission_integrity_token(
                        self._admission_secret,
                        token,
                    ),
                )
                self._register_prepared_admission_locked(token)
                return token
        except (StateError, ValueError):
            self._registry.cancel_prepared_admission(application_token)
            raise

    def cancel_prepared_admission(self, token: HttpChannelAdmissionToken) -> bool:
        """Cancel one unclaimed HTTP/common reservation without canonical mutation."""

        integrity_error: StateError | None = None
        with self._gate.mutation(), self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                return False
            try:
                capability = self._active_prepared_admission_locked(token)
            except StateError as error:
                integrity_error = error
                self._release_prepared_capability_locked(capability)
            else:
                if capability.reservation_id in self._claimed_admissions:
                    return False
                self._release_prepared_capability_locked(capability)
        common_error: StateError | None = None
        try:
            self._registry.cancel_prepared_admission(capability.application_token)
        except StateError as error:
            common_error = error
        if integrity_error is not None:
            raise integrity_error
        if common_error is not None:
            raise common_error
        return True

    def _claim_prepared_admission(
        self,
        token: HttpChannelAdmissionToken,
    ) -> _HttpAdmissionCapability:
        """Claim and revalidate one manager token without retaining HTTP locks."""

        failure: StateError | None = None
        capability: _HttpAdmissionCapability | None = None
        with self._gate.mutation(), self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            try:
                capability = self._active_prepared_admission_locked(token)
                if capability.reservation_id in self._claimed_admissions:
                    raise StateError("HTTP channel admission token is already claimed")
                if capability.linearization_time < self._watermark:
                    raise StateError("HTTP channel admission starts behind the canonical watermark")
                if not self._registry.authenticates_admission_token(capability.application_token):
                    raise StateError(
                        "HTTP admission's common application token failed authentication"
                    )
                self._validate_prepared_sidecar_locked(capability)
                self._active_prepared_admission_locked(token)
            except StateError as error:
                failure = error
                if capability is not None:
                    self._release_prepared_capability_locked(capability)
            else:
                self._claimed_admissions.add(capability.reservation_id)
                return capability
        if capability is not None:
            try:
                self._registry.cancel_prepared_admission(capability.application_token)
            except StateError:
                pass
        assert failure is not None
        raise failure

    @contextmanager
    def prepared_admission(
        self,
        token: HttpChannelAdmissionToken,
    ) -> Iterator[HttpChannelPreparedCommit]:
        """Claim HTTP and common tokens while retaining no locks across the body."""

        capability = self._claim_prepared_admission(token)
        transaction: HttpChannelPreparedCommit | None = None
        try:
            with self._registry.prepared_admission(
                capability.application_token
            ) as application_commit:
                transaction = HttpChannelPreparedCommit(
                    self,
                    token,
                    application_commit,
                )
                try:
                    yield transaction
                finally:
                    transaction._close()
        except BaseException:
            try:
                self._registry.cancel_prepared_admission(capability.application_token)
            except StateError:
                pass
            raise
        finally:
            if transaction is None or not transaction.committed:
                self._cancel_claimed_admission(token)

    def _cancel_claimed_admission(self, token: HttpChannelAdmissionToken) -> None:
        """Release one manager claim after its external transaction aborts."""

        with self._gate.mutation(), self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                return
            try:
                self._active_prepared_admission_locked(token)
            except StateError:
                self._release_prepared_capability_locked(capability)
                return
            if capability.reservation_id not in self._claimed_admissions:
                raise StateError("HTTP channel admission token is not claimed")
            self._release_prepared_capability_locked(capability)

    def _commit_claimed_admission(
        self,
        token: HttpChannelAdmissionToken,
        application_commit: ApplicationChannelPreparedCommit,
    ) -> HttpChannelAdmissionResult:
        """Commit one fully validated common admission, then its HTTP sidecar."""

        with self._gate.mutation(), self._prepared_lock:
            capability = self._active_prepared_admission_locked(token)
            if capability.reservation_id not in self._claimed_admissions:
                raise StateError("HTTP channel admission token is not claimed")
            if not self._registry.authenticates_admission_token(capability.application_token):
                raise StateError("HTTP admission's common application token failed authentication")
            self._validate_prepared_sidecar_locked(capability)
            self._active_prepared_admission_locked(token)
            trusted_token = capability.trusted_token
            application_result = application_commit.commit_no_fail()
            application_receipt = application_result.receipt
            assert application_receipt is not None
            assert self._registry.authenticates_admission_receipt(application_receipt)
            assert (
                application_receipt.publication_token
                == trusted_token.application_token.publication_token
            )
            assert application_receipt.snapshot == application_result.snapshot
            assert application_receipt.close_token == application_result.close_token
            assert application_receipt.channel_id == trusted_token.result.channel_id
            if isinstance(trusted_token.result, HttpChannelReuse):
                assert application_receipt.operation_id == trusted_token.result.operation_id
                assert (
                    application_result.snapshot.reserved_operations
                    == trusted_token.result.trans_depth
                )
            if trusted_token.kind == "open_transport":
                transport = trusted_token.prepared_transport
                assert transport is not None
                shard = self._shard(capability.owner_id, create=True)
                assert shard is not None
                with shard.lock:
                    expected = trusted_token.expected_transport
                    if expected is not None:
                        self._discard_sidecar_locked(shard, expected.channel_id)
                    transport_handle = shard.transports.insert(transport)
                    shard.transport_expiry.set(
                        transport_handle,
                        transport.reuse_deadline.timestamp(),
                    )
            receipt = HttpChannelAdmissionReceipt(
                manager_kind="http",
                manager_id=self._manager_id,
                kind=trusted_token.kind,
                publication_token=capability.integrity_token,
                application_receipt=application_receipt,
                application_receipt_token=application_receipt.receipt_token,
                channel_id=application_receipt.channel_id,
                operation_id=application_receipt.operation_id,
                transport_id=application_receipt.snapshot.identity.binding.transport_id,
                sidecar_result=trusted_token.result,
                sidecar_result_digest=http_channel_sidecar_result_digest(trusted_token.result),
                _manager_token=id(self),
            )
            receipt = replace(
                receipt,
                _integrity_token=_http_admission_receipt_integrity_token(
                    self._admission_secret,
                    receipt,
                ),
            )
            self._admission_receipts[id(receipt)] = receipt
            result = HttpChannelAdmissionResult(
                result=trusted_token.result,
                application=application_result,
                receipt=receipt,
            )
            self._release_prepared_capability_locked(capability)
            return result

    def get_transport(self, channel_id: str) -> HttpChannelTransport | None:
        """Return one open HTTP transport view through exact primary lookup."""

        shard_id = self._registry.owner_partition_for_channel(channel_id)
        if shard_id is None:
            return None
        shard = self._shards.get(shard_id)
        if shard is None:
            return None
        with shard.lock:
            return shard.transports.get(channel_id)

    def close_transport(
        self,
        channel_id: str,
        *,
        closed_at: datetime,
        reason: str,
    ) -> bool:
        """Finalize an open HTTP channel idempotently and discard its sidecar."""

        snapshot = self._registry.get(channel_id)
        if snapshot is None:
            return False
        shard = self._shard(snapshot.identity.owner_id, create=False)
        if shard is None:
            return False
        with self._gate.mutation(), self._prepared_lock, shard.lock:
            self._reject_prepared_conflict_locked(
                owner_id=snapshot.identity.owner_id,
                channel_ids=(channel_id,),
                affinity_digests=(snapshot.identity.affinity_digest,),
            )
            if shard.transports.get(channel_id) is None:
                return False
            self._retire_locked(
                shard,
                channel_id,
                at=ensure_utc(closed_at),
                reason=reason,
            )
            return True

    @staticmethod
    def _discard_sidecar_locked(shard: _HttpTransportShard, channel_id: str) -> None:
        transport = shard.transports.get(channel_id)
        if transport is not None:
            handle = shard.transports.handle_for(channel_id)
            shard.transports.delete(channel_id)
            shard.transport_deletions += 1
            shard.transport_expiry.pop(handle, None)

    def _retire_locked(
        self,
        shard: _HttpTransportShard,
        channel_id: str,
        *,
        at: datetime,
        reason: str,
    ) -> None:
        snapshot = self._registry.get(channel_id)
        if snapshot is not None and snapshot.is_open:
            effective_deadline = min(
                snapshot.idle_deadline,
                snapshot.identity.hard_deadline,
                snapshot.identity.binding.closes_at,
            )
            close_time = min(
                effective_deadline,
                max(ensure_utc(at), snapshot.identity.opened_at, snapshot.last_activity_at),
            )
            self._registry.close_channel(
                channel_id,
                closed_at=close_time,
                reason=reason,
            )
        self._discard_sidecar_locked(shard, channel_id)

    def _compact_sidecars(self, max_work: int) -> int:
        """Advance open-sidecar map rotations outside the global watermark gate."""

        if max_work <= 0:
            return 0
        with self._directory_lock:
            shards = tuple(sorted(self._shards.values(), key=lambda item: item.shard_id))
        if not shards:
            return 0
        work = 0
        visited = 0
        while visited < len(shards) and work < max_work:
            position = self._compaction_cursor % len(shards)
            shard = shards[position]
            visited += 1
            with shard.lock:
                metrics = shard.transports.metrics()
                if shard.transport_deletions or metrics.primary_compaction_pending:
                    inspected = shard.transports.compact_primary(
                        max_slots=max_work - work,
                        force=(
                            not metrics.primary_compaction_pending
                            and bool(shard.transport_deletions)
                            and metrics.live_entries == 0
                        ),
                    )
                    work += inspected
                pending = shard.transports.metrics().primary_compaction_pending
                if not pending:
                    shard.transport_deletions = 0
            if pending:
                self._compaction_cursor = position
                break
            self._compaction_cursor = (position + 1) % len(shards)
        return work

    def watermark(self, at: datetime) -> HttpChannelCensus:
        """Drain due sidecars and, for a private fallback, the common registry."""

        canonical_time = ensure_utc(at)
        with self._watermark_lane:
            with self._gate.watermark():
                if canonical_time < self._watermark:
                    raise StateError("HTTP watermarks must be monotonic")
                with self._prepared_lock:
                    claimed_frontier = min(
                        (
                            capability.linearization_time
                            for capability in self._prepared_capabilities.values()
                            if capability.reservation_id in self._claimed_admissions
                        ),
                        default=None,
                    )
                    reserved_channel_ids = frozenset(self._prepared_channel_ids)
                if claimed_frontier is not None and canonical_time > claimed_frontier:
                    raise StateError(
                        "HTTP watermark cannot advance past a claimed admission at "
                        f"{claimed_frontier.isoformat()}"
                    )
                cutoff = canonical_time.timestamp()
                with self._directory_lock:
                    shards = tuple(self._shards[index] for index in sorted(self._shards))
                for shard in shards:
                    while True:
                        reserved_due = False
                        with shard.lock:
                            due = shard.transport_expiry.expire_before_page(
                                cutoff,
                                inclusive=True,
                                limit=_PRIMARY_COMPACTION_WORK_PER_WATERMARK,
                            )
                            for transport_handle, deadline in due:
                                try:
                                    transport = shard.transports.get_by_handle(transport_handle)
                                except KeyError:
                                    continue
                                if transport.channel_id in reserved_channel_ids:
                                    shard.transport_expiry.set(transport_handle, deadline)
                                    reserved_due = True
                                    continue
                                self._retire_locked(
                                    shard,
                                    transport.channel_id,
                                    at=datetime.fromtimestamp(
                                        deadline,
                                        tz=canonical_time.tzinfo,
                                    ),
                                    reason="reuse deadline",
                                )
                        if not due or reserved_due:
                            break
                if self._owns_registry:
                    self._registry.watermark(canonical_time)
                self._watermark = canonical_time
            self._compact_sidecars(_PRIMARY_COMPACTION_WORK_PER_WATERMARK)
            return self.census()

    def census(self) -> HttpChannelCensus:
        """Return constant-time retained-state and expiry-amplification metrics."""

        with self._directory_lock:
            shards = tuple(self._shards.values())
        open_transport_views = 0
        max_shard_load = 0
        estimated_bytes = (
            sys.getsizeof(self) + sys.getsizeof(self.__dict__) + sys.getsizeof(self._shards)
        )
        transport_expiry_entries = 0
        stale_transport_expiry_entries = 0
        estimated_index_bytes = 0
        decoded_cache_entries = 0
        decoded_cache_bytes = 0
        sidecar_lookup_candidates = 0
        primary_metrics: list[IndexMetrics] = []
        for shard in shards:
            with shard.lock:
                shard_size = len(shard.transports)
                open_transport_views += shard_size
                max_shard_load = max(max_shard_load, shard_size)
                transport_metrics = shard.primary_metrics()
                expiry_metrics = shard.transport_expiry.metrics(estimate_bytes=True)
                primary_metrics.append(transport_metrics)
                sidecar_lookup_candidates += transport_metrics.lookup_candidates_inspected
                transport_expiry_entries += expiry_metrics.backing_entries
                stale_transport_expiry_entries += expiry_metrics.stale_entries
                decoded_cache_entries += shard.transports.decoded_cache_entries
                decoded_cache_bytes += shard.transports.decoded_cache_estimated_bytes
                estimated_index_bytes += (
                    transport_metrics.estimated_bytes + expiry_metrics.estimated_bytes
                )
                estimated_bytes += (
                    sys.getsizeof(shard)
                    + shard.transports.estimated_value_bytes
                    + transport_metrics.estimated_bytes
                    + expiry_metrics.estimated_bytes
                )
        primary_map_bytes = sum(metric.primary_map_backing_bytes for metric in primary_metrics)
        ideal_map_bytes = (
            len(primary_metrics) * _EMPTY_PRIMARY_MAP_BYTES
            + open_transport_views * _ESTIMATED_PRIMARY_HASH_ENTRY_BYTES
        )
        application = self._registry.census()
        return HttpChannelCensus(
            open_transport_views=open_transport_views,
            transport_expiry_entries=transport_expiry_entries,
            stale_transport_expiry_entries=stale_transport_expiry_entries,
            shard_count=len(shards),
            max_shard_load=max_shard_load,
            estimated_bytes=estimated_bytes,
            sidecar_estimated_index_bytes=estimated_index_bytes,
            decoded_cache_entries=decoded_cache_entries,
            decoded_cache_capacity=(len(shards) * _DECODED_CACHE_CAPACITY_PER_SHARD),
            decoded_cache_estimated_bytes=decoded_cache_bytes,
            lookup_candidates_inspected=(
                sidecar_lookup_candidates + application.lookup_candidates_inspected
            ),
            sidecar_lookup_candidates_inspected=sidecar_lookup_candidates,
            transport_primary_map_bytes=primary_map_bytes,
            transport_primary_map_amplification=primary_map_bytes / max(1, ideal_map_bytes),
            transport_primary_compaction_pending=sum(
                metric.primary_compaction_pending for metric in primary_metrics
            ),
            transport_primary_compaction_rotations=sum(
                metric.primary_compaction_rotations for metric in primary_metrics
            ),
            transport_primary_compaction_work=sum(
                metric.primary_compaction_work for metric in primary_metrics
            ),
            transport_primary_compaction_seconds=sum(
                metric.primary_compaction_seconds for metric in primary_metrics
            ),
            application=application,
        )

    def channel_snapshot(self, channel_id: str) -> ApplicationChannelSnapshot | None:
        """Return one frozen registry snapshot for diagnostics and focused tests."""

        return self._registry.get(channel_id)

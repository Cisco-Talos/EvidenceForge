# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Duration-stable registry for protocol-neutral application channels.

Mutable channel ownership is partitioned by a stable owner digest. Exact ID
routes are partitioned independently, so unrelated owners never contend on one
registry-wide mutation lock. Completed operations collapse to counters plus a
bounded used-ID marker retained only until the owning channel tombstone expires.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import sys
from array import array
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field, fields, replace
from datetime import UTC, datetime, timedelta
from threading import Condition, Lock, RLock
from typing import Literal, cast

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelCensus,
    ApplicationChannelIdentity,
    ApplicationChannelSnapshot,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.generation.indexes import (
    CompactIndexedStore,
    IncrementalExactMap,
    IndexMetrics,
    PackedByteRowStore,
    PackedHandleExpiryIndex,
    PackedUniqueDigestMap,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc

_DEFAULT_CLOSED_GRACE = timedelta(seconds=30)
_DEFAULT_MAX_REUSABLE_PER_AFFINITY = 8
_DEFAULT_SHARD_COUNT = 64
_USED_ID_PURGE_PAGE = 256
_PRIMARY_COMPACTION_WORK_PER_WATERMARK = 4_096
_ROUTE_COMPACTION_WORK_PER_WATERMARK = 4_096
_ROUTE_PARTITION_RECLAIM_PER_WATERMARK = 64
_EXPIRY_COMPACTION_WORK_PER_WATERMARK = 4_096
_EXPIRY_PAGE_SIZE = 4_096
_DECODED_CACHE_PER_SHARD = 256
_MAX_RECOVERABLE_ADMISSION_RESULTS = 4_096
_MAX_PREPARED_CLOSE_PROJECTION_TEXT_BYTES = 4_096
_MAX_PREPARED_CLOSE_PROJECTION_PAYLOAD_BYTES = 96 * 1_024
_MAX_APPLICATION_ADMISSION_MEMBERS = 64
_MAX_APPLICATION_ADMISSION_PAYLOAD_BYTES = 2 * 1024 * 1024
_EMPTY_PRIMARY_MAP_BYTES = sys.getsizeof({})
_EMPTY_PACKED_ROUTE_MAP_BYTES = 2 * sys.getsizeof(array("Q", [0]) * 8)
_ESTIMATED_ROUTE_HASH_ENTRY_BYTES = 40

# Fixed structural estimates cover compact-store slots, equality memberships,
# and route values. Variable canonical value sizes are mutation-accounted below.
_ESTIMATED_CHANNEL_INDEX_BYTES = 224
_ESTIMATED_OPERATION_INDEX_BYTES = 160
_ESTIMATED_USED_ID_INDEX_BYTES = 112
_ESTIMATED_PACKED_ROUTE_VALUE_BYTES = sys.getsizeof(1 << 32)
_PACKED_USED_ID_INLINE_BYTES = 80
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_PACKED_CHANNEL_NUMERIC_BYTES = struct.calcsize("<I4q2Q3I") + struct.calcsize("<4q2QI")


def _datetime_us(value: datetime) -> int:
    """Return an exact signed microsecond offset from the Unix epoch."""

    canonical = value if value.tzinfo is UTC else ensure_utc(value)
    delta = canonical - _EPOCH
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000) + delta.microseconds


def _datetime_from_us(value: int) -> datetime:
    """Reconstruct one exact UTC datetime from a signed microsecond offset."""

    return _EPOCH + timedelta(microseconds=value)


class _PackedDigestMultiIndex:
    """Packed equality index with lazy linked buckets for duplicate digests."""

    _EMPTY = 2**64 - 1
    _BUCKET_FLAG = 1 << 31

    __slots__ = (
        "_bucket_heads",
        "_bucket_sizes",
        "_bucket_tails",
        "_count",
        "_free_buckets",
        "_keys",
        "_max_bucket_size",
        "_memberships",
        "_next",
        "_previous",
        "_values",
    )

    def __init__(self) -> None:
        self._keys = array("Q", [self._EMPTY]) * 8
        self._values = array("I", [0]) * 8
        self._count = 0
        self._bucket_heads = array("q")
        self._bucket_tails = array("q")
        self._bucket_sizes = array("I")
        self._free_buckets = array("I")
        self._memberships = array("I")
        self._previous = array("q")
        self._next = array("q")
        self._max_bucket_size = 0

    @property
    def bucket_count(self) -> int:
        return self._count

    @property
    def max_bucket_size(self) -> int:
        return self._max_bucket_size

    def _find_slot(self, digest: int) -> tuple[int, bool]:
        position = digest & (len(self._keys) - 1)
        while True:
            retained = self._keys[position]
            if retained == self._EMPTY:
                return position, False
            if retained == digest:
                return position, True
            position = (position + 1) & (len(self._keys) - 1)

    def _resize(self, capacity: int) -> None:
        prior_keys = self._keys
        prior_values = self._values
        self._keys = array("Q", [self._EMPTY]) * capacity
        self._values = array("I", [0]) * capacity
        for position, digest in enumerate(prior_keys):
            if digest == self._EMPTY:
                continue
            target, _found = self._find_slot(digest)
            self._keys[target] = digest
            self._values[target] = prior_values[position]

    def _ensure_handle(self, handle: int) -> None:
        missing = handle + 1 - len(self._memberships)
        if missing <= 0:
            return
        self._memberships.extend(array("I", [0]) * missing)
        self._previous.extend(array("q", [-1]) * missing)
        self._next.extend(array("q", [-1]) * missing)

    def _new_bucket(self, first: int, second: int) -> int:
        if self._free_buckets:
            bucket = self._free_buckets.pop()
            self._bucket_heads[bucket] = first
            self._bucket_tails[bucket] = second
            self._bucket_sizes[bucket] = 2
        else:
            bucket = len(self._bucket_heads)
            if bucket >= self._BUCKET_FLAG:
                raise OverflowError("Packed application equality buckets exhausted")
            self._bucket_heads.append(first)
            self._bucket_tails.append(second)
            self._bucket_sizes.append(2)
        self._ensure_handle(max(first, second))
        self._memberships[first] = bucket + 1
        self._memberships[second] = bucket + 1
        self._previous[first] = -1
        self._next[first] = second
        self._previous[second] = first
        self._next[second] = -1
        return bucket

    def add(self, digest: int, handle: int) -> None:
        if handle < 0 or handle >= self._BUCKET_FLAG:
            raise OverflowError("Packed application equality handle exceeds 31-bit capacity")
        position, found = self._find_slot(digest)
        if not found and (self._count + 1) * 4 > len(self._keys) * 3:
            self._resize(len(self._keys) * 2)
            position, found = self._find_slot(digest)
        if not found:
            self._keys[position] = digest
            self._values[position] = handle
            self._count += 1
            self._max_bucket_size = max(self._max_bucket_size, 1)
            return
        value = self._values[position]
        if value < self._BUCKET_FLAG:
            bucket = self._new_bucket(value, handle)
            self._values[position] = self._BUCKET_FLAG | bucket
            self._max_bucket_size = max(self._max_bucket_size, 2)
            return
        bucket = value & (self._BUCKET_FLAG - 1)
        self._ensure_handle(handle)
        tail = self._bucket_tails[bucket]
        self._memberships[handle] = bucket + 1
        self._previous[handle] = tail
        self._next[handle] = -1
        self._next[tail] = handle
        self._bucket_tails[bucket] = handle
        self._bucket_sizes[bucket] += 1
        self._max_bucket_size = max(self._max_bucket_size, self._bucket_sizes[bucket])

    def _delete_position(self, gap: int) -> None:
        mask = len(self._keys) - 1
        position = (gap + 1) & mask
        while self._keys[position] != self._EMPTY:
            home = self._keys[position] & mask
            if ((position - home) & mask) >= ((gap - home) & mask):
                self._keys[gap] = self._keys[position]
                self._values[gap] = self._values[position]
                gap = position
            position = (position + 1) & mask
        self._keys[gap] = self._EMPTY
        self._values[gap] = 0

    def remove(self, digest: int, handle: int) -> None:
        position, found = self._find_slot(digest)
        if not found:
            return
        value = self._values[position]
        if value < self._BUCKET_FLAG:
            if value == handle:
                self._delete_position(position)
                self._count -= 1
            return
        bucket = value & (self._BUCKET_FLAG - 1)
        if handle >= len(self._memberships) or self._memberships[handle] != bucket + 1:
            return
        previous = self._previous[handle]
        following = self._next[handle]
        if previous >= 0:
            self._next[previous] = following
        else:
            self._bucket_heads[bucket] = following
        if following >= 0:
            self._previous[following] = previous
        else:
            self._bucket_tails[bucket] = previous
        self._memberships[handle] = 0
        self._previous[handle] = -1
        self._next[handle] = -1
        self._bucket_sizes[bucket] -= 1
        if self._bucket_sizes[bucket] == 1:
            remaining = self._bucket_heads[bucket]
            self._memberships[remaining] = 0
            self._previous[remaining] = -1
            self._next[remaining] = -1
            self._values[position] = remaining
            self._bucket_sizes[bucket] = 0
            self._free_buckets.append(bucket)

    def iter_handles(self, digest: int) -> Iterator[int]:
        position, found = self._find_slot(digest)
        if not found:
            return
        value = self._values[position]
        if value < self._BUCKET_FLAG:
            yield value
            return
        bucket = value & (self._BUCKET_FLAG - 1)
        handle = self._bucket_heads[bucket]
        while handle >= 0:
            yield handle
            handle = self._next[handle]

    def count(self, digest: int) -> int:
        """Return one exact digest bucket size without traversing its handles."""

        position, found = self._find_slot(digest)
        if not found:
            return 0
        encoded = self._values[position]
        if encoded < self._BUCKET_FLAG:
            return 1
        return self._bucket_sizes[encoded - self._BUCKET_FLAG]

    def page(
        self,
        digest: int,
        *,
        after_handle: int | None,
        limit: int,
    ) -> tuple[tuple[int, ...], int | None]:
        position, found = self._find_slot(digest)
        if not found:
            return (), None
        value = self._values[position]
        if value < self._BUCKET_FLAG:
            if after_handle is None:
                return (value,), None
            if after_handle != value:
                raise KeyError(f"stale packed index page cursor {after_handle}")
            return (), None
        bucket = value & (self._BUCKET_FLAG - 1)
        if after_handle is None:
            handle = self._bucket_heads[bucket]
        else:
            if (
                after_handle >= len(self._memberships)
                or self._memberships[after_handle] != bucket + 1
            ):
                raise KeyError(f"stale packed index page cursor {after_handle}")
            handle = self._next[after_handle]
        page: list[int] = []
        while handle >= 0 and len(page) < limit:
            page.append(handle)
            handle = self._next[handle]
        return tuple(page), (page[-1] if page and handle >= 0 else None)

    def estimated_bytes(self) -> int:
        """Return packed table and lazily allocated duplicate-bucket bytes."""

        return sum(
            sys.getsizeof(value)
            for value in (
                self,
                self._keys,
                self._values,
                self._bucket_heads,
                self._bucket_tails,
                self._bucket_sizes,
                self._free_buckets,
                self._memberships,
                self._previous,
                self._next,
            )
        )


class _PackedChannelPlanPool:
    """Dense immutable timing/budget rows aligned with channel handles."""

    _PLAN = struct.Struct("<4q2QI")

    __slots__ = ("_active", "_plans")

    def __init__(self) -> None:
        self._plans = bytearray()
        self._active = bytearray()

    @classmethod
    def _pack(cls, identity: ApplicationChannelIdentity) -> bytes:
        budget = identity.budget
        if budget.initiator_bytes >= 2**64 or budget.responder_bytes >= 2**64:
            raise StateError("Application channel byte budget exceeds packed 64-bit limit")
        if budget.operations >= 2**32:
            raise StateError("Application channel operation budget exceeds packed 32-bit limit")
        return cls._PLAN.pack(
            _datetime_us(identity.binding.opened_at),
            _datetime_us(identity.binding.closes_at),
            identity.idle_timeout // timedelta(microseconds=1),
            _datetime_us(identity.hard_deadline),
            budget.initiator_bytes,
            budget.responder_bytes,
            budget.operations,
        )

    def acquire(self, identity: ApplicationChannelIdentity, *, handle: int) -> int:
        """Store one plan at its owning compact channel handle."""

        if handle < 0 or handle >= 2**32 - 1:
            raise StateError("Application channel plan handle exceeds packed capacity")
        missing = handle + 1 - len(self._active)
        if missing > 0:
            self._active.extend(b"\0" * missing)
            self._plans.extend(b"\0" * (missing * self._PLAN.size))
        if self._active[handle]:
            raise StateError("Application channel plan handle is already active")
        start = handle * self._PLAN.size
        self._plans[start : start + self._PLAN.size] = self._pack(identity)
        self._active[handle] = 1
        return handle

    def release(self, handle: int) -> None:
        """Release one live plan and recycle it after its last channel expires."""

        if handle < 0 or handle >= len(self._active) or not self._active[handle]:
            raise KeyError(handle)
        start = handle * self._PLAN.size
        self._plans[start : start + self._PLAN.size] = b"\0" * self._PLAN.size
        self._active[handle] = 0

    def values(self, handle: int) -> tuple[int, ...]:
        """Return one immutable plan's primitive values by exact handle."""

        if handle < 0 or handle >= len(self._active) or not self._active[handle]:
            raise KeyError(handle)
        return self._PLAN.unpack_from(self._plans, handle * self._PLAN.size)


@dataclass(frozen=True, slots=True)
class _PreparedChannelIdentity:
    """Transient packed identity and equality keys for one admission."""

    identity: ApplicationChannelIdentity
    owner_key: int
    affinity_key: int
    payload: bytes


class _PackedChannelStore:
    """Dense primitive channel columns with on-demand frozen reconstruction."""

    _NUMERIC = struct.Struct("<I4q2Q3I")
    _EMPTY_IDENTITY = 2**32 - 1

    __slots__ = (
        "_affinity_index",
        "_close_reason_codes",
        "_close_reason_refcounts",
        "_close_reason_routes",
        "_close_reason_value_bytes",
        "_close_reason_values",
        "_decoded_cache",
        "_decoded_cache_value_bytes",
        "_free_handles",
        "_free_close_reason_codes",
        "_generations",
        "_high_water_mark",
        "_identity_capacities",
        "_identity_data",
        "_identity_lengths",
        "_identity_offsets",
        "_live_count",
        "_owner_index",
        "_owner_keys",
        "_affinity_keys",
        "_plans",
        "_records",
    )

    def __init__(self) -> None:
        self._identity_data = bytearray()
        self._identity_offsets = array("I")
        self._identity_lengths = array("I")
        self._identity_capacities = array("I")
        self._records = bytearray()
        self._close_reason_codes = array("I")
        self._close_reason_values: list[str | None] = [None]
        self._close_reason_refcounts = array("I", [0])
        self._close_reason_routes: dict[str, int] = {}
        self._close_reason_value_bytes = 0
        self._free_close_reason_codes = array("I")
        self._decoded_cache: OrderedDict[int, ApplicationChannelSnapshot] = OrderedDict()
        self._decoded_cache_value_bytes = 0
        self._free_handles = array("I")
        self._generations = array("I")
        self._owner_index = _PackedDigestMultiIndex()
        self._affinity_index = _PackedDigestMultiIndex()
        self._owner_keys = array("Q")
        self._affinity_keys = array("Q")
        self._plans = _PackedChannelPlanPool()
        self._live_count = 0
        self._high_water_mark = 0

    def __len__(self) -> int:
        return self._live_count

    @property
    def decoded_cache_entries(self) -> int:
        """Return the bounded number of reconstructed immutable views."""

        return len(self._decoded_cache)

    @property
    def decoded_cache_estimated_bytes(self) -> int:
        """Return constant-time backing and value bytes for decoded views."""

        return sys.getsizeof(self._decoded_cache) + self._decoded_cache_value_bytes

    def _discard_decoded(self, handle: int) -> None:
        snapshot = self._decoded_cache.pop(handle, None)
        if snapshot is not None:
            self._decoded_cache_value_bytes -= _decoded_snapshot_estimated_bytes(snapshot)
        if not self._decoded_cache:
            self._decoded_cache.clear()

    def _retain_decoded(self, handle: int, snapshot: ApplicationChannelSnapshot) -> None:
        prior = self._decoded_cache.pop(handle, None)
        if prior is not None:
            self._decoded_cache_value_bytes -= _decoded_snapshot_estimated_bytes(prior)
        self._decoded_cache[handle] = snapshot
        self._decoded_cache_value_bytes += _decoded_snapshot_estimated_bytes(snapshot)
        while len(self._decoded_cache) > _DECODED_CACHE_PER_SHARD:
            _evicted_handle, evicted = self._decoded_cache.popitem(last=False)
            self._decoded_cache_value_bytes -= _decoded_snapshot_estimated_bytes(evicted)

    @staticmethod
    def _text_key(namespace: bytes, *values: str) -> int:
        digest = hashlib.blake2b(digest_size=8, person=namespace)
        for value in values:
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        return int.from_bytes(digest.digest(), "big")

    @classmethod
    def _owner_key(cls, owner_id: str) -> int:
        return cls._text_key(b"eforge-own-v1", owner_id)

    @classmethod
    def _affinity_key(cls, owner_id: str, affinity_digest: str) -> int:
        if len(affinity_digest) == 64:
            try:
                # Protocol affinities are already SHA-256 identities.  Reuse
                # their uniformly distributed prefix as the equality bucket
                # key; exact packed identity comparison still resolves the
                # vanishingly rare 64-bit collision.
                return int(affinity_digest[:16], 16) & (2**64 - 2)
            except ValueError:
                pass
        return cls._text_key(b"eforge-aff-v1", owner_id, affinity_digest)

    @staticmethod
    def _pack_identity(identity: ApplicationChannelIdentity) -> bytes:
        encoded = (
            identity.channel_id.encode("utf-8"),
            identity.protocol.encode("utf-8"),
            identity.owner_id.encode("utf-8"),
            identity.affinity_digest.encode("utf-8"),
            identity.binding.transport_id.encode("utf-8"),
        )
        payload = bytearray()
        for value in encoded:
            length = len(value)
            if length >= _PackedChannelStore._EMPTY_IDENTITY:
                raise StateError("Application channel identity field exceeds packed 32-bit length")
            while length >= 0x80:
                payload.append((length & 0x7F) | 0x80)
                length >>= 7
            payload.append(length)
            payload.extend(value)
        return bytes(payload)

    @classmethod
    def prepare_identity(cls, identity: ApplicationChannelIdentity) -> _PreparedChannelIdentity:
        """Compute immutable packed identity work once before admission locks."""

        return _PreparedChannelIdentity(
            identity=identity,
            owner_key=cls._owner_key(identity.owner_id),
            affinity_key=cls._affinity_key(identity.owner_id, identity.affinity_digest),
            payload=cls._pack_identity(identity),
        )

    def _identity_values(self, handle: int) -> tuple[str, str, str, str, str]:
        length = self._identity_lengths[handle]
        if length == self._EMPTY_IDENTITY:
            raise KeyError(handle)
        offset = self._identity_offsets[handle]
        end = offset + length
        cursor = offset
        values: list[str] = []
        for _field in range(5):
            field_length = 0
            shift = 0
            while True:
                part = self._identity_data[cursor]
                cursor += 1
                field_length |= (part & 0x7F) << shift
                if not part & 0x80:
                    break
                shift += 7
            field_end = cursor + field_length
            if field_end > end:
                raise StateError("Packed application channel identity is truncated")
            values.append(bytes(self._identity_data[cursor:field_end]).decode("utf-8"))
            cursor = field_end
        return cast(tuple[str, str, str, str, str], tuple(values))

    def _channel_id_value(self, handle: int) -> str:
        """Decode only the leading semantic channel ID from one packed row."""

        self._require_live(handle)
        cursor = self._identity_offsets[handle]
        field_length = 0
        shift = 0
        while True:
            part = self._identity_data[cursor]
            cursor += 1
            field_length |= (part & 0x7F) << shift
            if not part & 0x80:
                break
            shift += 7
        return bytes(self._identity_data[cursor : cursor + field_length]).decode("utf-8")

    def _is_live(self, handle: int) -> bool:
        return (
            0 <= handle < len(self._identity_lengths)
            and self._identity_lengths[handle] != self._EMPTY_IDENTITY
        )

    def _require_live(self, handle: int) -> None:
        if not self._is_live(handle):
            raise KeyError(handle)

    @staticmethod
    def _numeric_values(
        plan_handle: int,
        snapshot: ApplicationChannelSnapshot,
    ) -> tuple[int, ...]:
        values = (
            plan_handle,
            _datetime_us(snapshot.identity.opened_at),
            _datetime_us(snapshot.last_activity_at),
            _datetime_us(snapshot.idle_deadline),
            -1 if snapshot.closed_at is None else _datetime_us(snapshot.closed_at),
            snapshot.reserved_initiator_bytes,
            snapshot.reserved_responder_bytes,
            snapshot.reserved_operations,
            snapshot.completed_operations,
            snapshot.active_operations,
        )
        if any(value >= 2**64 for value in values[5:7]) or any(
            value >= 2**32 for value in values[7:]
        ):
            raise StateError("Application channel counters exceed packed 64/32-bit limits")
        return values

    def _write_snapshot(
        self,
        handle: int,
        snapshot: ApplicationChannelSnapshot,
        *,
        plan_handle: int | None = None,
    ) -> None:
        self._discard_decoded(handle)
        if plan_handle is None:
            plan_handle = self._NUMERIC.unpack_from(self._records, handle * self._NUMERIC.size)[0]
        numeric = self._NUMERIC.pack(*self._numeric_values(plan_handle, snapshot))
        self._set_close_reason(handle, snapshot.close_reason)
        start = handle * self._NUMERIC.size
        self._records[start : start + self._NUMERIC.size] = numeric

    def _close_reason(self, handle: int) -> str:
        code = self._close_reason_codes[handle]
        if code == 0:
            return ""
        reason = self._close_reason_values[code]
        if reason is None:
            raise StateError("Application channel close-reason code is stale")
        return reason

    def _set_close_reason(self, handle: int, reason: str) -> None:
        """Assign one exact interned reason and release the prior compact code."""

        prior_code = self._close_reason_codes[handle]
        if reason:
            target_code = self._close_reason_routes.get(reason)
            if target_code is None:
                if self._free_close_reason_codes:
                    target_code = self._free_close_reason_codes.pop()
                    self._close_reason_values[target_code] = reason
                    self._close_reason_refcounts[target_code] = 0
                else:
                    target_code = len(self._close_reason_values)
                    if target_code >= 2**32:
                        raise StateError("Application close-reason pool exhausted 32-bit codes")
                    self._close_reason_values.append(reason)
                    self._close_reason_refcounts.append(0)
                self._close_reason_routes[reason] = target_code
                self._close_reason_value_bytes += sys.getsizeof(reason)
            if target_code == prior_code:
                return
            if self._close_reason_refcounts[target_code] == 2**32 - 1:
                raise StateError("Application close-reason reference count overflow")
            self._close_reason_refcounts[target_code] += 1
        else:
            target_code = 0
            if prior_code == 0:
                return
        self._close_reason_codes[handle] = target_code
        if prior_code == 0:
            return
        prior_refs = self._close_reason_refcounts[prior_code]
        if prior_refs == 0:
            raise StateError("Application close-reason reference count underflow")
        prior_refs -= 1
        self._close_reason_refcounts[prior_code] = prior_refs
        if prior_refs:
            return
        prior_reason = self._close_reason_values[prior_code]
        if prior_reason is None:
            raise StateError("Application close-reason code lost its canonical value")
        if self._close_reason_routes.get(prior_reason) == prior_code:
            del self._close_reason_routes[prior_reason]
        self._close_reason_value_bytes -= sys.getsizeof(prior_reason)
        self._close_reason_values[prior_code] = None
        self._free_close_reason_codes.append(prior_code)

    @staticmethod
    def _new_value(value_type: type[object], **values: object) -> object:
        value = object.__new__(value_type)
        for name, field_value in values.items():
            object.__setattr__(value, name, field_value)
        return value

    def _materialize(self, handle: int) -> ApplicationChannelSnapshot:
        self._require_live(handle)
        cached = self._decoded_cache.get(handle)
        if cached is not None:
            self._decoded_cache.move_to_end(handle)
            return cached
        numeric = self._NUMERIC.unpack_from(self._records, handle * self._NUMERIC.size)
        plan = self._plans.values(numeric[0])
        channel_id, protocol, owner_id, affinity_digest, transport_id = self._identity_values(
            handle
        )
        binding = cast(
            ApplicationTransportBinding,
            self._new_value(
                ApplicationTransportBinding,
                transport_id=transport_id,
                opened_at=_datetime_from_us(plan[0]),
                closes_at=_datetime_from_us(plan[1]),
            ),
        )
        budget = cast(
            ApplicationChannelBudget,
            self._new_value(
                ApplicationChannelBudget,
                initiator_bytes=plan[4],
                responder_bytes=plan[5],
                operations=plan[6],
            ),
        )
        identity = cast(
            ApplicationChannelIdentity,
            self._new_value(
                ApplicationChannelIdentity,
                channel_id=channel_id,
                protocol=protocol,
                owner_id=owner_id,
                affinity_digest=affinity_digest,
                binding=binding,
                opened_at=_datetime_from_us(numeric[1]),
                idle_timeout=timedelta(microseconds=plan[2]),
                hard_deadline=_datetime_from_us(plan[3]),
                budget=budget,
            ),
        )
        snapshot = cast(
            ApplicationChannelSnapshot,
            self._new_value(
                ApplicationChannelSnapshot,
                identity=identity,
                last_activity_at=_datetime_from_us(numeric[2]),
                idle_deadline=_datetime_from_us(numeric[3]),
                reserved_initiator_bytes=numeric[5],
                reserved_responder_bytes=numeric[6],
                reserved_operations=numeric[7],
                completed_operations=numeric[8],
                active_operations=numeric[9],
                closed_at=None if numeric[4] < 0 else _datetime_from_us(numeric[4]),
                close_reason=self._close_reason(handle),
            ),
        )
        self._retain_decoded(handle, snapshot)
        return snapshot

    def insert(
        self,
        snapshot: ApplicationChannelSnapshot,
        *,
        prepared_identity: _PreparedChannelIdentity | None = None,
    ) -> int:
        """Insert one frozen snapshot and return its reusable compact handle."""

        identity = snapshot.identity
        if prepared_identity is None:
            prepared_identity = self.prepare_identity(identity)
        elif prepared_identity.identity is not identity:
            raise StateError("Prepared application channel identity does not match its snapshot")

        if self._free_handles:
            handle = self._free_handles.pop()
        else:
            handle = len(self._identity_lengths)
            if handle >= 2**32 - 1:
                raise StateError("Application channel store exhausted 32-bit handles")
            self._identity_offsets.append(0)
            self._identity_lengths.append(self._EMPTY_IDENTITY)
            self._identity_capacities.append(0)
            self._generations.append(0)
            self._close_reason_codes.append(0)
            self._owner_keys.append(0)
            self._affinity_keys.append(0)
            self._records.extend(b"\0" * self._NUMERIC.size)
        if self._generations[handle] == 2**32 - 1:
            self._free_handles.append(handle)
            raise StateError("Application channel handle exhausted its generation counter")
        self._generations[handle] += 1
        owner_key = prepared_identity.owner_key
        affinity_key = prepared_identity.affinity_key
        self._owner_keys[handle] = owner_key
        self._affinity_keys[handle] = affinity_key
        payload = prepared_identity.payload
        capacity = self._identity_capacities[handle]
        if len(payload) > capacity:
            offset = len(self._identity_data)
            if offset + len(payload) >= 2**32:
                raise StateError("Application channel identity slab exceeds 32-bit capacity")
            self._identity_data.extend(payload)
            self._identity_offsets[handle] = offset
            self._identity_capacities[handle] = len(payload)
        else:
            offset = self._identity_offsets[handle]
            self._identity_data[offset : offset + len(payload)] = payload
        try:
            plan_handle = self._plans.acquire(identity, handle=handle)
        except (OverflowError, StateError):
            self._free_handles.append(handle)
            raise
        self._identity_lengths[handle] = len(payload)
        try:
            self._write_snapshot(handle, snapshot, plan_handle=plan_handle)
        except (OverflowError, StateError):
            self._plans.release(plan_handle)
            self._identity_lengths[handle] = self._EMPTY_IDENTITY
            self._free_handles.append(handle)
            raise
        if snapshot.is_open:
            self._owner_index.add(owner_key, handle)
            self._affinity_index.add(affinity_key, handle)
        self._live_count += 1
        self._high_water_mark = max(self._high_water_mark, self._live_count)
        return handle

    def count_prepared_affinity(self, prepared_identity: _PreparedChannelIdentity) -> int:
        """Return an exact affinity cardinality using one precomputed digest."""

        identity = prepared_identity.identity
        return sum(
            self._affinity_matches(handle, identity.owner_id, identity.affinity_digest)
            for handle in self._affinity_index.iter_handles(prepared_identity.affinity_key)
        )

    def replace(
        self,
        handle: int,
        snapshot: ApplicationChannelSnapshot,
        *,
        known_prior: ApplicationChannelSnapshot | None = None,
    ) -> ApplicationChannelSnapshot:
        """Replace mutable primitive columns while preserving immutable identity."""

        if known_prior is None:
            prior = self._materialize(handle)
        else:
            self._require_live(handle)
            retained_channel_id = self._identity_values(handle)[0]
            if retained_channel_id != known_prior.channel_id:
                raise StateError("Known application channel prior does not match its handle")
            prior = known_prior
        if snapshot.identity != prior.identity:
            raise StateError("Application channel identity cannot change after opening")
        if prior.is_open and not snapshot.is_open:
            self._owner_index.remove(self._owner_keys[handle], handle)
            self._affinity_index.remove(self._affinity_keys[handle], handle)
        elif not prior.is_open and snapshot.is_open:
            raise StateError("Closed application channels cannot reopen")
        self._write_snapshot(handle, snapshot)
        return prior

    def delete(self, handle: int) -> ApplicationChannelSnapshot:
        """Delete a retained channel and recycle its dense handle."""

        prior = self._materialize(handle)
        if prior.is_open:
            self._owner_index.remove(self._owner_keys[handle], handle)
            self._affinity_index.remove(self._affinity_keys[handle], handle)
        plan_handle = self._NUMERIC.unpack_from(self._records, handle * self._NUMERIC.size)[0]
        self._discard_decoded(handle)
        self._plans.release(plan_handle)
        self._set_close_reason(handle, "")
        self._identity_lengths[handle] = self._EMPTY_IDENTITY
        start = handle * self._NUMERIC.size
        self._records[start : start + self._NUMERIC.size] = b"\0" * self._NUMERIC.size
        self._free_handles.append(handle)
        self._live_count -= 1
        return prior

    def get_by_handle(self, handle: int) -> ApplicationChannelSnapshot:
        """Return one reconstructed frozen snapshot by exact handle."""

        return self._materialize(handle)

    def detached_by_handle(self, handle: int) -> ApplicationChannelSnapshot:
        """Return a frozen snapshot without warming an otherwise-cold decoded cache."""

        retained = self._decoded_cache.get(handle)
        if retained is not None:
            return retained
        snapshot = self._materialize(handle)
        self._discard_decoded(handle)
        return snapshot

    def generation(self, handle: int) -> int:
        """Return the current ABA generation for one live compact handle."""

        self._require_live(handle)
        return self._generations[handle]

    def estimated_row_bytes(self, handle: int) -> int:
        """Return the mutation-accounted packed value size in constant time."""

        self._require_live(handle)
        return (
            _PACKED_CHANNEL_NUMERIC_BYTES + self._identity_lengths[handle] + 3 * array("I").itemsize
        )

    def matches(self, handle: int, generation: int, channel_id: str) -> bool:
        """Return whether one handle token still owns an exact semantic channel."""

        if not self._is_live(handle) or self._generations[handle] != generation:
            return False
        return self._channel_id_value(handle) == channel_id

    def close_primitive(
        self,
        handle: int,
        *,
        generation: int,
        channel_id: str,
        closed_at_us: int,
        reason: str,
    ) -> tuple[bool, int]:
        """Close one exact row without reconstructing its frozen object graph."""

        if not self.matches(handle, generation, channel_id):
            raise StateError(f"Stale application channel close token for {channel_id!r}")
        numeric = list(self._NUMERIC.unpack_from(self._records, handle * self._NUMERIC.size))
        retained_closed_at = numeric[4]
        if retained_closed_at >= 0:
            return False, retained_closed_at
        if numeric[9]:
            raise StateError(
                f"Application channel {channel_id!r} cannot close with "
                f"{numeric[9]} active operations"
            )
        plan = self._plans.values(numeric[0])
        if closed_at_us < numeric[1]:
            raise StateError("Application channel cannot close before it opens")
        if closed_at_us > min(numeric[3], plan[1], plan[3]):
            raise StateError(
                "Application channel cannot close after its idle, hard, or transport deadline"
            )
        self._discard_decoded(handle)
        self._owner_index.remove(self._owner_keys[handle], handle)
        self._affinity_index.remove(self._affinity_keys[handle], handle)
        numeric[4] = closed_at_us
        start = handle * self._NUMERIC.size
        self._records[start : start + self._NUMERIC.size] = self._NUMERIC.pack(*numeric)
        self._set_close_reason(handle, reason)
        return True, closed_at_us

    def eviction_identity(
        self,
        handle: int,
    ) -> tuple[int, str, str, bool, int, int]:
        """Return minimal versioned route fields for one retained row."""

        self._require_live(handle)
        numeric = self._NUMERIC.unpack_from(self._records, handle * self._NUMERIC.size)
        channel_id, _protocol, _owner, _affinity, transport_id = self._identity_values(handle)
        estimated_value_bytes = self.estimated_row_bytes(handle)
        return (
            self._generations[handle],
            channel_id,
            transport_id,
            numeric[4] < 0,
            numeric[9],
            estimated_value_bytes,
        )

    def delete_primitive(
        self,
        handle: int,
        *,
        generation: int,
        channel_id: str,
    ) -> tuple[str, int]:
        """Delete one exact closed row without materializing canonical values."""

        (
            retained_generation,
            retained_channel,
            transport_id,
            is_open,
            _active_operations,
            estimated_bytes,
        ) = self.eviction_identity(handle)
        if retained_generation != generation or retained_channel != channel_id:
            raise StateError(f"Stale application channel eviction token for {channel_id!r}")
        if is_open:
            raise StateError(f"Application channel {channel_id!r} is still open")
        plan_handle = self._NUMERIC.unpack_from(self._records, handle * self._NUMERIC.size)[0]
        self._discard_decoded(handle)
        self._plans.release(plan_handle)
        self._set_close_reason(handle, "")
        self._identity_lengths[handle] = self._EMPTY_IDENTITY
        start = handle * self._NUMERIC.size
        self._records[start : start + self._NUMERIC.size] = b"\0" * self._NUMERIC.size
        self._free_handles.append(handle)
        self._live_count -= 1
        return transport_id, estimated_bytes

    def _affinity_matches(self, handle: int, owner_id: str, affinity_digest: str) -> bool:
        _channel, _protocol, retained_owner, retained_affinity, _transport = self._identity_values(
            handle
        )
        return retained_owner == owner_id and retained_affinity == affinity_digest

    def find_iter(
        self, index_name: str, indexed_value: object
    ) -> Iterator[ApplicationChannelSnapshot]:
        """Yield exact current-state matches without materializing a broad registry."""

        if index_name == "owner":
            if isinstance(indexed_value, str):
                for handle in self._owner_index.iter_handles(self._owner_key(indexed_value)):
                    if self._identity_values(handle)[2] == indexed_value:
                        yield self._materialize(handle)
            return
        if index_name != "affinity":
            raise KeyError(f"unknown packed channel index {index_name!r}")
        if not (
            isinstance(indexed_value, tuple)
            and len(indexed_value) == 2
            and all(isinstance(value, str) for value in indexed_value)
        ):
            return
        owner_id, affinity_digest = cast(tuple[str, str], indexed_value)
        key = self._affinity_key(owner_id, affinity_digest)
        for handle in self._affinity_index.iter_handles(key):
            if self._affinity_matches(handle, owner_id, affinity_digest):
                yield self._materialize(handle)

    def find_handle_page(
        self,
        index_name: str,
        indexed_value: object,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[int, ...], int | None]:
        """Return one bounded exact owner page and resumable handle cursor."""

        if limit <= 0:
            raise ValueError("Packed channel page limit must be positive")
        if index_name != "owner" or not isinstance(indexed_value, str):
            raise KeyError(f"unknown packed channel page index {index_name!r}")
        return self._owner_index.page(
            self._owner_key(indexed_value),
            after_handle=after_handle,
            limit=limit,
        )

    def handle_for_channel(self, owner_id: str, channel_id: str) -> int | None:
        """Return one exact owner-local handle even if its route was not installed."""

        for handle in self._owner_index.iter_handles(self._owner_key(owner_id)):
            if self._channel_id_value(handle) == channel_id:
                return handle
        return None

    def recovery_handle_for_channel(self, owner_id: str, channel_id: str) -> int | None:
        """Find an ambiguously inserted row, including an already-closed row.

        This exceptional recovery scan is intentionally not used on the normal
        open path. Closed rows do not belong to the reusable owner index, so a
        lost return from an insertion needs the dense-row fallback.
        """

        indexed = self.handle_for_channel(owner_id, channel_id)
        if indexed is not None:
            return indexed
        for handle, length in enumerate(self._identity_lengths):
            if length == self._EMPTY_IDENTITY:
                continue
            retained_channel, _protocol, retained_owner, _affinity, _transport = (
                self._identity_values(handle)
            )
            if retained_owner == owner_id and retained_channel == channel_id:
                return handle
        return None

    def count(self, index_name: str, indexed_value: object) -> int:
        """Return one exact owner or owner-affinity cardinality."""

        if index_name == "owner":
            if not isinstance(indexed_value, str):
                return 0
            return sum(
                self._identity_values(handle)[2] == indexed_value
                for handle in self._owner_index.iter_handles(self._owner_key(indexed_value))
            )
        if index_name != "affinity":
            raise KeyError(f"unknown packed channel index {index_name!r}")
        if not (
            isinstance(indexed_value, tuple)
            and len(indexed_value) == 2
            and all(isinstance(value, str) for value in indexed_value)
        ):
            return 0
        owner_id, affinity_digest = cast(tuple[str, str], indexed_value)
        key = self._affinity_key(owner_id, affinity_digest)
        return sum(
            self._affinity_matches(handle, owner_id, affinity_digest)
            for handle in self._affinity_index.iter_handles(key)
        )

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return structural handle and equality-index metrics without row scans."""

        estimated_bytes = 0
        if estimate_bytes:
            estimated_bytes = (
                sys.getsizeof(self)
                + sys.getsizeof(self._identity_offsets)
                + sys.getsizeof(self._generations)
                + sys.getsizeof(self._owner_keys)
                + sys.getsizeof(self._affinity_keys)
                + sys.getsizeof(self._close_reason_codes)
                + sys.getsizeof(self._close_reason_values)
                + sys.getsizeof(self._close_reason_refcounts)
                + sys.getsizeof(self._close_reason_routes)
                + sys.getsizeof(self._free_close_reason_codes)
                + self._close_reason_value_bytes
                + sys.getsizeof(self._free_handles)
                + self._owner_index.estimated_bytes()
                + self._affinity_index.estimated_bytes()
            )
        return IndexMetrics(
            live_entries=self._live_count,
            backing_entries=len(self._identity_lengths),
            stale_entries=len(self._free_handles),
            allocated_slots=len(self._identity_lengths),
            secondary_buckets=(self._owner_index.bucket_count + self._affinity_index.bucket_count),
            max_bucket_size=max(
                self._owner_index.max_bucket_size, self._affinity_index.max_bucket_size
            ),
            high_water_mark=self._high_water_mark,
            estimated_bytes=estimated_bytes,
        )


class _PackedUsedOperationIds:
    """Compact exact completed-operation markers grouped by channel handle."""

    _HEADER = struct.Struct("<II")
    _EMPTY_HANDLE = 2**32 - 1

    def __init__(self) -> None:
        self._single_rows = PackedByteRowStore(inline_slot_bytes=64, chunk_slots=256)
        self._single_handles = array("I")
        self._single_count = 0
        self._rows = PackedByteRowStore(
            inline_slot_bytes=_PACKED_USED_ID_INLINE_BYTES,
            chunk_slots=256,
        )
        self._routes = PackedUniqueDigestMap(b"ef-used-op")
        self._channels = _PackedDigestMultiIndex()

    def __len__(self) -> int:
        return self._single_count + len(self._rows)

    def _ensure_channel(self, channel_handle: int) -> None:
        missing = channel_handle + 1 - len(self._single_handles)
        if missing > 0:
            self._single_handles.extend(array("I", [self._EMPTY_HANDLE]) * missing)

    def _single_operation(self, channel_handle: int) -> str | None:
        if channel_handle < 0 or channel_handle >= len(self._single_handles):
            return None
        row_handle = self._single_handles[channel_handle]
        if row_handle == self._EMPTY_HANDLE:
            return None
        return bytes(self._single_rows.get_by_handle(row_handle)).decode("utf-8")

    @staticmethod
    def _digest(channel_handle: int, operation_id: str) -> int:
        digest = hashlib.blake2b(digest_size=8, person=b"ef-used-op")
        digest.update(channel_handle.to_bytes(4, "little"))
        digest.update(operation_id.encode("utf-8"))
        return int.from_bytes(digest.digest(), "big") & (2**64 - 2)

    @classmethod
    def _pack(cls, channel_handle: int, operation_id: str) -> bytes:
        encoded = operation_id.encode("utf-8")
        if len(encoded) >= 2**32:
            raise StateError("Application operation_id exceeds packed 32-bit length")
        return cls._HEADER.pack(channel_handle, len(encoded)) + encoded

    @classmethod
    def _unpack(cls, row: bytes | memoryview) -> tuple[int, str]:
        channel_handle, length = cls._HEADER.unpack_from(row)
        start = cls._HEADER.size
        if start + length != len(row):
            raise StateError("Packed application operation marker is truncated")
        return channel_handle, bytes(row[start:]).decode("utf-8")

    def _resolve_digest(
        self,
        digest: int,
        channel_handle: int,
        operation_id: str,
    ) -> int | None:
        handle = self._routes.get_digest(digest)
        if handle is None:
            return None
        retained_channel, retained_operation = self._unpack(self._rows.get_by_handle(handle))
        if retained_channel != channel_handle or retained_operation != operation_id:
            raise StateError("Application completed-operation digest collision")
        return handle

    def _resolve(self, channel_handle: int, operation_id: str) -> tuple[int, int] | None:
        digest = self._digest(channel_handle, operation_id)
        handle = self._resolve_digest(digest, channel_handle, operation_id)
        return None if handle is None else (digest, handle)

    def __contains__(self, key: object) -> bool:
        if not (
            isinstance(key, tuple)
            and len(key) == 2
            and isinstance(key[0], int)
            and isinstance(key[1], str)
        ):
            return False
        single = self._single_operation(key[0])
        return single == key[1] or self._resolve(key[0], key[1]) is not None

    def __setitem__(self, key: tuple[int, str], value: int) -> None:
        channel_handle, operation_id = key
        if value != channel_handle:
            raise StateError("Application completed-operation marker has the wrong owner handle")
        self._ensure_channel(channel_handle)
        single = self._single_operation(channel_handle)
        if single is None:
            row_handle = self._single_rows.insert(operation_id.encode("utf-8"))
            self._single_handles[channel_handle] = row_handle
            self._single_count += 1
            return
        if single == operation_id:
            raise KeyError(key)
        digest = self._digest(channel_handle, operation_id)
        if self._resolve_digest(digest, channel_handle, operation_id) is not None:
            raise KeyError(key)
        row = self._pack(channel_handle, operation_id)
        handle = self._rows.insert(row)
        self._routes.set_digest(digest, handle)
        self._channels.add(channel_handle, handle)

    def __delitem__(self, key: tuple[int, str]) -> None:
        channel_handle, operation_id = key
        if self._single_operation(channel_handle) == operation_id:
            row_handle = self._single_handles[channel_handle]
            self._single_rows.delete(row_handle)
            self._single_handles[channel_handle] = self._EMPTY_HANDLE
            self._single_count -= 1
            return
        routed = self._resolve(channel_handle, operation_id)
        if routed is None:
            raise KeyError(key)
        digest, handle = routed
        self._routes.pop_digest(digest)
        self._channels.remove(channel_handle, handle)
        self._rows.delete(handle)

    def delete_handle(self, handle: int) -> tuple[int, str]:
        """Delete one known marker handle with one row decode and one route probe."""

        channel_handle, operation_id = self._unpack(self._rows.get_by_handle(handle))
        digest = self._digest(channel_handle, operation_id)
        if self._routes.get_digest(digest) != handle:
            raise StateError("Application completed-operation route no longer matches its row")
        self._routes.pop_digest(digest)
        self._channels.remove(channel_handle, handle)
        self._rows.delete(handle)
        return channel_handle, operation_id

    def count(self, index_name: str, indexed_value: object) -> int:
        if index_name != "channel":
            raise KeyError(f"unknown packed used-ID index {index_name!r}")
        if not isinstance(indexed_value, int):
            return 0
        return (1 if self._single_operation(indexed_value) is not None else 0) + (
            self._channels.count(indexed_value)
        )

    def purge_channel(
        self,
        channel_handle: int,
        *,
        limit: int,
    ) -> tuple[tuple[tuple[int, str], ...], bool]:
        """Delete one bounded marker page, taking the inline singleton first."""

        if limit <= 0:
            raise ValueError("Application used-ID purge limit must be positive")
        removed: list[tuple[int, str]] = []
        single = self._single_operation(channel_handle)
        if single is not None:
            row_handle = self._single_handles[channel_handle]
            self._single_rows.delete(row_handle)
            self._single_handles[channel_handle] = self._EMPTY_HANDLE
            self._single_count -= 1
            removed.append((channel_handle, single))
        remaining = limit - len(removed)
        if remaining:
            handles, _cursor = self._channels.page(
                channel_handle,
                after_handle=None,
                limit=remaining,
            )
            for handle in handles:
                removed.append(self.delete_handle(handle))
        return tuple(removed), self.count("channel", channel_handle) > 0

    def find_handle_page(
        self,
        index_name: str,
        indexed_value: object,
        *,
        limit: int,
    ) -> tuple[tuple[int, ...], int | None]:
        if index_name != "channel" or not isinstance(indexed_value, int):
            raise KeyError(f"unknown packed used-ID index {index_name!r}")
        return self._channels.page(indexed_value, after_handle=None, limit=limit)

    def key_by_handle(self, handle: int) -> tuple[int, str]:
        return self._unpack(self._rows.get_by_handle(handle))

    def compact_primary(self, *, max_slots: int = 4_096, force: bool = False) -> int:
        if max_slots < 0:
            raise ValueError("Application used-ID compaction budget cannot be negative")
        self._routes.compact_primary(max_entries=max_slots, force=force)
        return 0

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        single_rows = self._single_rows.metrics(estimate_bytes=estimate_bytes)
        rows = self._rows.metrics(estimate_bytes=estimate_bytes)
        routes = self._routes.metrics(estimate_bytes=estimate_bytes)
        return IndexMetrics(
            live_entries=single_rows.live_entries + rows.live_entries,
            backing_entries=single_rows.backing_entries + rows.backing_entries,
            stale_entries=single_rows.stale_entries + rows.stale_entries,
            allocated_slots=single_rows.allocated_slots + rows.allocated_slots,
            secondary_buckets=self._channels.bucket_count,
            max_bucket_size=self._channels.max_bucket_size,
            high_water_mark=single_rows.high_water_mark + rows.high_water_mark,
            estimated_bytes=(
                single_rows.estimated_bytes
                + rows.estimated_bytes
                + routes.estimated_bytes
                + (sys.getsizeof(self._single_handles) if estimate_bytes else 0)
                + (self._channels.estimated_bytes() if estimate_bytes else 0)
            ),
            primary_map_entries=routes.primary_map_entries,
            primary_map_backing_bytes=routes.primary_map_backing_bytes,
            primary_compaction_pending=routes.primary_compaction_pending,
            primary_compaction_rotations=routes.primary_compaction_rotations,
            primary_compaction_work=routes.primary_compaction_work,
            primary_compaction_seconds=routes.primary_compaction_seconds,
        )


@dataclass(frozen=True, slots=True)
class ApplicationChannelCloseToken:
    """Opaque compact locator protected against recycled-handle ABA."""

    locator: int
    generation: int

    def __post_init__(self) -> None:
        """Reject tokens outside their packed unsigned ranges."""

        if not 0 <= self.locator < 2**32:
            raise ValueError("Application channel close-token locator must fit 32 bits")
        if not 0 < self.generation < 2**32:
            raise ValueError("Application channel close-token generation must fit 32 bits")


@dataclass(frozen=True, slots=True)
class ApplicationChannelCloseRequest:
    """One bounded fast-close request from a protocol sidecar."""

    channel_id: str
    token: ApplicationChannelCloseToken
    closed_at: datetime
    reason: str


@dataclass(frozen=True, slots=True)
class ApplicationChannelRetirementProof:
    """Registry-authenticated terminal snapshot that survives tombstone expiry."""

    snapshot: ApplicationChannelSnapshot
    _registry_token: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")

    @property
    def proof_token(self) -> str:
        """Return the opaque keyed proof over the terminal snapshot."""

        return self._integrity_token


@dataclass(frozen=True, slots=True)
class ApplicationChannelCloseResult:
    """Minimal authoritative outcome from a versioned channel close."""

    channel_id: str
    closed_at: datetime
    newly_closed: bool
    retirement_proof: ApplicationChannelRetirementProof | None = None


@dataclass(frozen=True, slots=True)
class ApplicationChannelAdmissionToken:
    """Opaque reservation for one coupled channel mutation.

    Preparation reserves semantic IDs and affinity capacity without publishing
    a channel or operation.  The token remains caller-owned until it is
    cancelled or claimed by :meth:`ApplicationChannelRegistry.prepared_admission`.
    """

    kind: Literal[
        "open_completed",
        "open_completed_batch_close",
        "open_completed_close",
        "completed_operation",
        "completed_operation_close",
    ]
    reservation: ApplicationOperationReservation
    reservations: tuple[ApplicationOperationReservation, ...] = ()
    identity: ApplicationChannelIdentity | None = None
    replacement_channel_id: str = ""
    replacement_closed_at: datetime | None = None
    replacement_reason: str = ""
    channel_closed_at: datetime | None = None
    channel_close_reason: str = ""
    _registry_token: int = field(repr=False, default=0)
    _reservation_id: int = field(repr=False, default=0)
    _owner_shard_id: int = field(repr=False, default=0)
    _channel_handle: int | None = field(repr=False, default=None)
    _channel_generation: int | None = field(repr=False, default=None)
    _expected_snapshot: ApplicationChannelSnapshot | None = field(repr=False, default=None)
    _prepared_snapshot: ApplicationChannelSnapshot | None = field(repr=False, default=None)
    _reserved_channel_ids: tuple[str, ...] = field(repr=False, default=())
    _reserved_transport_ids: tuple[str, ...] = field(repr=False, default=())
    _retain_result_for_recovery: bool = field(repr=False, default=False)
    _integrity_token: str = field(repr=False, default="")

    @property
    def linearization_time(self) -> datetime:
        """Return the canonical time that a claimed token fences."""

        candidates = [
            reservation.started_at for reservation in (self.reservations or (self.reservation,))
        ]
        if self.identity is not None:
            candidates.append(self.identity.opened_at)
        if self.replacement_closed_at is not None:
            candidates.append(self.replacement_closed_at)
        if self.channel_closed_at is not None:
            candidates.append(self.channel_closed_at)
        return min(candidates)

    @property
    def publication_token(self) -> str:
        """Return the stable opaque capability binding for external coordinators."""

        return self._integrity_token


def _application_channel_admission_integrity_token(
    authority_secret: bytes,
    token: ApplicationChannelAdmissionToken,
) -> str:
    """Authenticate every public and private prepared-admission field."""

    return hmac.new(
        authority_secret,
        _application_channel_admission_token_payload(token),
        hashlib.sha256,
    ).hexdigest()


def _application_channel_admission_token_is_authentic(
    authority_secret: bytes,
    token: object,
) -> bool:
    """Return a total callback-free authentication decision for one admission token."""

    if type(token) is not ApplicationChannelAdmissionToken:
        return False
    try:
        expected = _application_channel_admission_integrity_token(authority_secret, token)
        retained = _prepared_close_proof_digest(token._integrity_token, "token.integrity")
    except (AttributeError, TypeError, ValueError):
        return False
    return hmac.compare_digest(retained, expected)


@dataclass(frozen=True, slots=True)
class _ApplicationChannelAdmissionCapability:
    """Registry-owned immutable locator and trusted admission preimage."""

    token_id: int
    reservation_id: int
    integrity_token: str
    carrier_token: ApplicationChannelAdmissionToken
    trusted_token: ApplicationChannelAdmissionToken
    reserved_channel_ids: tuple[str, ...]
    reserved_transport_ids: tuple[str, ...]
    operation_ids: tuple[str, ...]
    affinity_key: tuple[str, str] | None
    linearization_time: datetime
    retain_result_for_recovery: bool


@dataclass(frozen=True, slots=True)
class ApplicationChannelAdmissionReceipt:
    """Authenticated proof of one committed prepared channel admission."""

    kind: Literal[
        "open_completed",
        "open_completed_batch_close",
        "open_completed_close",
        "completed_operation",
        "completed_operation_close",
    ]
    publication_token: str
    channel_id: str
    operation_id: str
    operation_ids: tuple[str, ...]
    snapshot: ApplicationChannelSnapshot
    close_token: ApplicationChannelCloseToken | None = None
    _registry_token: int = field(repr=False, default=0)
    _recoverable: bool = field(repr=False, default=False)
    _integrity_token: str = field(repr=False, default="")

    @property
    def receipt_token(self) -> str:
        """Return the opaque keyed proof over the committed result."""

        return self._integrity_token


def _application_channel_admission_receipt_integrity_token(
    authority_secret: bytes,
    receipt: ApplicationChannelAdmissionReceipt,
) -> str:
    """Authenticate exact capability and committed result membership."""

    return hmac.new(
        authority_secret,
        _application_channel_admission_receipt_payload(receipt),
        hashlib.sha256,
    ).hexdigest()


def _application_channel_admission_receipt_is_authentic(
    authority_secret: bytes,
    receipt: object,
) -> bool:
    """Return a total callback-free authentication decision for one admission receipt."""

    if type(receipt) is not ApplicationChannelAdmissionReceipt:
        return False
    try:
        expected = _application_channel_admission_receipt_integrity_token(
            authority_secret,
            receipt,
        )
        retained = _prepared_close_proof_digest(receipt._integrity_token, "receipt.integrity")
    except (AttributeError, TypeError, ValueError):
        return False
    return hmac.compare_digest(retained, expected)


@dataclass(frozen=True, slots=True)
class ApplicationChannelAdmissionResult:
    """Frozen result of one prepared channel admission."""

    snapshot: ApplicationChannelSnapshot
    close_token: ApplicationChannelCloseToken | None = None
    receipt: ApplicationChannelAdmissionReceipt | None = None


@dataclass(frozen=True, slots=True)
class _RecoverableApplicationAdmissionResult:
    """Exact retained result for one acknowledged-or-retried outer transaction."""

    token: ApplicationChannelAdmissionToken
    result: ApplicationChannelAdmissionResult


@dataclass(frozen=True, slots=True)
class ApplicationChannelCommitRecovery:
    """Authenticated reconciliation of an exception during a common commit."""

    status: Literal["committed", "not_committed", "indeterminate"]
    result: ApplicationChannelAdmissionResult | None = None


@dataclass(frozen=True, slots=True)
class ApplicationChannelPreparedCloseToken:
    """Opaque exact reservation for a close-only channel mutation."""

    channel_id: str
    closed_at: datetime
    reason: str
    _registry_token: int = field(repr=False, default=0)
    _reservation_id: int = field(repr=False, default=0)
    _owner_shard_id: int = field(repr=False, default=0)
    _channel_handle: int = field(repr=False, default=0)
    _channel_generation: int = field(repr=False, default=0)
    _expected_snapshot: ApplicationChannelSnapshot | None = field(repr=False, default=None)
    _prepared_snapshot: ApplicationChannelSnapshot | None = field(repr=False, default=None)
    _integrity_token: str = field(repr=False, default="")

    @property
    def publication_token(self) -> str:
        """Return the keyed binding consumed by an outer close coordinator."""

        return self._integrity_token


def _prepared_close_proof_text(value: object, field_name: str) -> bytes:
    """Frame one exact bounded built-in string without invoking caller callbacks."""

    if type(value) is not str:
        raise ValueError(f"{field_name} must be an exact string")
    if len(value) > _MAX_PREPARED_CLOSE_PROJECTION_TEXT_BYTES:
        raise ValueError(f"{field_name} exceeds the prepared-close proof text bound")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field_name} must be valid UTF-8") from error
    if len(encoded) > _MAX_PREPARED_CLOSE_PROJECTION_TEXT_BYTES:
        raise ValueError(f"{field_name} exceeds the prepared-close proof text bound")
    return struct.pack(">I", len(encoded)) + encoded


def _prepared_close_proof_uint(value: object, bits: int, field_name: str) -> bytes:
    """Encode one exact unsigned scalar with a fixed public width."""

    if type(value) is not int or value < 0 or value >= 1 << bits:
        raise ValueError(f"{field_name} must be an unsigned {bits}-bit integer")
    if bits == 32:
        return struct.pack(">I", value)
    if bits == 64:
        return struct.pack(">Q", value)
    raise AssertionError("prepared-close proof integer width is internal")


def _prepared_close_proof_datetime(value: object, field_name: str) -> bytes:
    """Encode one exact UTC datetime as a signed fixed-width microsecond value."""

    if type(value) is not datetime or value.tzinfo is not UTC:
        raise ValueError(f"{field_name} must be an exact UTC datetime")
    microseconds = _datetime_us(value)
    if microseconds < -(1 << 63) or microseconds >= 1 << 63:
        raise ValueError(f"{field_name} exceeds the prepared-close datetime bound")
    return struct.pack(">q", microseconds)


def _prepared_close_proof_timedelta(value: object, field_name: str) -> bytes:
    """Encode one exact timedelta as signed fixed-width microseconds."""

    if type(value) is not timedelta:
        raise ValueError(f"{field_name} must be an exact timedelta")
    microseconds = ((value.days * 86_400 + value.seconds) * 1_000_000) + value.microseconds
    if microseconds < -(1 << 63) or microseconds >= 1 << 63:
        raise ValueError(f"{field_name} exceeds the prepared-close duration bound")
    return struct.pack(">q", microseconds)


def _prepared_close_proof_digest(value: object, field_name: str) -> str:
    """Validate one exact lowercase SHA-256/HMAC hexadecimal token."""

    if type(value) is not str or len(value) != 64:
        raise ValueError(f"{field_name} must be an exact 64-character digest")
    if any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{field_name} must be lowercase hexadecimal")
    return value


def _application_channel_identity_proof_payload(identity: object) -> bytes:
    """Return a callback-free bounded encoding of one exact channel identity tree."""

    if type(identity) is not ApplicationChannelIdentity:
        raise ValueError("prepared-close snapshot identity has an invalid exact type")
    binding = identity.binding
    budget = identity.budget
    if type(binding) is not ApplicationTransportBinding:
        raise ValueError("prepared-close transport binding has an invalid exact type")
    if type(budget) is not ApplicationChannelBudget:
        raise ValueError("prepared-close budget has an invalid exact type")
    payload = bytearray(b"application-channel-identity-proof-v1\0")
    payload.extend(_prepared_close_proof_text(identity.channel_id, "identity.channel_id"))
    payload.extend(_prepared_close_proof_text(identity.protocol, "identity.protocol"))
    payload.extend(_prepared_close_proof_text(identity.owner_id, "identity.owner_id"))
    payload.extend(_prepared_close_proof_text(identity.affinity_digest, "identity.affinity_digest"))
    payload.extend(
        _prepared_close_proof_text(binding.transport_id, "identity.binding.transport_id")
    )
    payload.extend(_prepared_close_proof_datetime(binding.opened_at, "identity.binding.opened_at"))
    payload.extend(_prepared_close_proof_datetime(binding.closes_at, "identity.binding.closes_at"))
    payload.extend(_prepared_close_proof_datetime(identity.opened_at, "identity.opened_at"))
    payload.extend(_prepared_close_proof_timedelta(identity.idle_timeout, "identity.idle_timeout"))
    payload.extend(_prepared_close_proof_datetime(identity.hard_deadline, "identity.hard_deadline"))
    payload.extend(
        _prepared_close_proof_uint(
            budget.initiator_bytes,
            64,
            "identity.budget.initiator_bytes",
        )
    )
    payload.extend(
        _prepared_close_proof_uint(
            budget.responder_bytes,
            64,
            "identity.budget.responder_bytes",
        )
    )
    payload.extend(_prepared_close_proof_uint(budget.operations, 32, "identity.budget.operations"))
    if len(payload) > _MAX_PREPARED_CLOSE_PROJECTION_PAYLOAD_BYTES:
        raise ValueError("prepared-close identity proof exceeds its payload bound")
    return bytes(payload)


def _application_channel_snapshot_proof_payload(snapshot: object) -> bytes:
    """Return a callback-free bounded encoding of one exact immutable snapshot tree."""

    if type(snapshot) is not ApplicationChannelSnapshot:
        raise ValueError("prepared-close snapshot has an invalid exact type")
    payload = bytearray(b"application-channel-snapshot-proof-v1\0")
    identity_payload = _application_channel_identity_proof_payload(snapshot.identity)
    payload.extend(struct.pack(">I", len(identity_payload)))
    payload.extend(identity_payload)
    payload.extend(
        _prepared_close_proof_datetime(snapshot.last_activity_at, "snapshot.last_activity_at")
    )
    payload.extend(_prepared_close_proof_datetime(snapshot.idle_deadline, "snapshot.idle_deadline"))
    payload.extend(
        _prepared_close_proof_uint(
            snapshot.reserved_initiator_bytes,
            64,
            "snapshot.reserved_initiator_bytes",
        )
    )
    payload.extend(
        _prepared_close_proof_uint(
            snapshot.reserved_responder_bytes,
            64,
            "snapshot.reserved_responder_bytes",
        )
    )
    payload.extend(
        _prepared_close_proof_uint(
            snapshot.reserved_operations,
            32,
            "snapshot.reserved_operations",
        )
    )
    payload.extend(
        _prepared_close_proof_uint(
            snapshot.completed_operations,
            32,
            "snapshot.completed_operations",
        )
    )
    payload.extend(
        _prepared_close_proof_uint(
            snapshot.active_operations,
            32,
            "snapshot.active_operations",
        )
    )
    if snapshot.closed_at is None:
        payload.extend(b"\0")
    else:
        payload.extend(b"\1")
        payload.extend(_prepared_close_proof_datetime(snapshot.closed_at, "snapshot.closed_at"))
    payload.extend(_prepared_close_proof_text(snapshot.close_reason, "snapshot.close_reason"))
    if len(payload) > _MAX_PREPARED_CLOSE_PROJECTION_PAYLOAD_BYTES:
        raise ValueError("prepared-close snapshot proof exceeds its payload bound")
    return bytes(payload)


def _application_channel_retirement_proof_integrity_token(
    authority_secret: bytes,
    proof: ApplicationChannelRetirementProof,
) -> str:
    """Authenticate one exact terminal snapshot independently of retained rows."""

    payload = bytearray(b"application-channel-retirement-proof-v1\0")
    payload.extend(
        _prepared_close_proof_uint(
            proof._registry_token,
            64,
            "retirement.registry",
        )
    )
    snapshot_payload = _application_channel_snapshot_proof_payload(proof.snapshot)
    payload.extend(struct.pack(">I", len(snapshot_payload)))
    payload.extend(snapshot_payload)
    return hmac.new(authority_secret, bytes(payload), hashlib.sha256).hexdigest()


def _application_admission_optional_datetime(value: object, field_name: str) -> bytes:
    """Frame one exact optional UTC timestamp."""

    if value is None:
        return b"\0"
    return b"\1" + _prepared_close_proof_datetime(value, field_name)


def _application_admission_optional_uint(
    value: object,
    bits: int,
    field_name: str,
) -> bytes:
    """Frame one exact optional unsigned scalar."""

    if value is None:
        return b"\0"
    return b"\1" + _prepared_close_proof_uint(value, bits, field_name)


def _application_admission_text_tuple(value: object, field_name: str) -> bytes:
    """Frame one bounded exact tuple of strings without sorting or callbacks."""

    if type(value) is not tuple or len(value) > _MAX_APPLICATION_ADMISSION_MEMBERS:
        raise ValueError(f"{field_name} must be an exact tuple within the admission bound")
    payload = bytearray(struct.pack(">I", len(value)))
    for ordinal, item in enumerate(value):
        payload.extend(_prepared_close_proof_text(item, f"{field_name}[{ordinal}]"))
    return bytes(payload)


def _application_operation_reservation_proof_payload(reservation: object) -> bytes:
    """Encode one exact operation reservation with a fixed closed schema."""

    if type(reservation) is not ApplicationOperationReservation:
        raise ValueError("application admission reservation has an invalid exact type")
    payload = bytearray(b"application-operation-reservation-proof-v1\0")
    payload.extend(_prepared_close_proof_text(reservation.operation_id, "reservation.operation_id"))
    payload.extend(_prepared_close_proof_text(reservation.channel_id, "reservation.channel_id"))
    payload.extend(_prepared_close_proof_uint(reservation.ordinal, 64, "reservation.ordinal"))
    payload.extend(_prepared_close_proof_datetime(reservation.started_at, "reservation.started_at"))
    payload.extend(_prepared_close_proof_datetime(reservation.ended_at, "reservation.ended_at"))
    payload.extend(
        _prepared_close_proof_uint(
            reservation.initiator_bytes,
            64,
            "reservation.initiator_bytes",
        )
    )
    payload.extend(
        _prepared_close_proof_uint(
            reservation.responder_bytes,
            64,
            "reservation.responder_bytes",
        )
    )
    payload.extend(
        _prepared_close_proof_text(
            reservation.parent_operation_id,
            "reservation.parent_operation_id",
        )
    )
    if len(payload) > _MAX_PREPARED_CLOSE_PROJECTION_PAYLOAD_BYTES:
        raise ValueError("application operation reservation proof exceeds its payload bound")
    return bytes(payload)


def _application_channel_admission_token_payload(token: object) -> bytes:
    """Encode one exact admission capability without dynamic representations."""

    if type(token) is not ApplicationChannelAdmissionToken:
        raise ValueError("application admission token has an invalid exact type")
    if token.kind not in {
        "open_completed",
        "open_completed_batch_close",
        "open_completed_close",
        "completed_operation",
        "completed_operation_close",
    }:
        raise ValueError("application admission token kind is invalid")
    if type(token.reservations) is not tuple or len(token.reservations) > (
        _MAX_APPLICATION_ADMISSION_MEMBERS
    ):
        raise ValueError("application admission reservation tuple exceeds its exact bound")
    payload = bytearray(b"application-channel-admission-v2\0")
    payload.extend(_prepared_close_proof_text(token.kind, "token.kind"))
    reservation_payload = _application_operation_reservation_proof_payload(token.reservation)
    payload.extend(struct.pack(">I", len(reservation_payload)))
    payload.extend(reservation_payload)
    payload.extend(struct.pack(">I", len(token.reservations)))
    for reservation in token.reservations:
        reservation_payload = _application_operation_reservation_proof_payload(reservation)
        payload.extend(struct.pack(">I", len(reservation_payload)))
        payload.extend(reservation_payload)
    if token.identity is None:
        payload.extend(b"\0")
    else:
        identity_payload = _application_channel_identity_proof_payload(token.identity)
        payload.extend(b"\1" + struct.pack(">I", len(identity_payload)))
        payload.extend(identity_payload)
    payload.extend(
        _prepared_close_proof_text(
            token.replacement_channel_id,
            "token.replacement_channel_id",
        )
    )
    payload.extend(
        _application_admission_optional_datetime(
            token.replacement_closed_at,
            "token.replacement_closed_at",
        )
    )
    payload.extend(_prepared_close_proof_text(token.replacement_reason, "token.replacement_reason"))
    payload.extend(
        _application_admission_optional_datetime(
            token.channel_closed_at,
            "token.channel_closed_at",
        )
    )
    payload.extend(
        _prepared_close_proof_text(token.channel_close_reason, "token.channel_close_reason")
    )
    payload.extend(_prepared_close_proof_uint(token._registry_token, 64, "token.registry"))
    payload.extend(_prepared_close_proof_uint(token._reservation_id, 64, "token.reservation"))
    payload.extend(_prepared_close_proof_uint(token._owner_shard_id, 32, "token.owner_shard"))
    payload.extend(_application_admission_optional_uint(token._channel_handle, 32, "token.handle"))
    payload.extend(
        _application_admission_optional_uint(
            token._channel_generation,
            32,
            "token.generation",
        )
    )
    for _field_name, snapshot in (
        ("token.expected_snapshot", token._expected_snapshot),
        ("token.prepared_snapshot", token._prepared_snapshot),
    ):
        if snapshot is None:
            payload.extend(b"\0")
        else:
            snapshot_payload = _application_channel_snapshot_proof_payload(snapshot)
            payload.extend(b"\1" + struct.pack(">I", len(snapshot_payload)))
            payload.extend(snapshot_payload)
    payload.extend(
        _application_admission_text_tuple(
            token._reserved_channel_ids,
            "token.reserved_channel_ids",
        )
    )
    payload.extend(
        _application_admission_text_tuple(
            token._reserved_transport_ids,
            "token.reserved_transport_ids",
        )
    )
    if type(token._retain_result_for_recovery) is not bool:
        raise ValueError("token.retain_result_for_recovery must be an exact bool")
    payload.extend(b"\1" if token._retain_result_for_recovery else b"\0")
    if len(payload) > _MAX_APPLICATION_ADMISSION_PAYLOAD_BYTES:
        raise ValueError("application admission token exceeds its aggregate payload bound")
    return bytes(payload)


def _application_channel_admission_receipt_payload(receipt: object) -> bytes:
    """Encode one exact admission receipt without dynamic representations."""

    if type(receipt) is not ApplicationChannelAdmissionReceipt:
        raise ValueError("application admission receipt has an invalid exact type")
    if receipt.kind not in {
        "open_completed",
        "open_completed_batch_close",
        "open_completed_close",
        "completed_operation",
        "completed_operation_close",
    }:
        raise ValueError("application admission receipt kind is invalid")
    publication_token = _prepared_close_proof_digest(
        receipt.publication_token,
        "receipt.publication_token",
    )
    payload = bytearray(b"application-channel-admission-receipt-v2\0")
    payload.extend(_prepared_close_proof_text(receipt.kind, "receipt.kind"))
    payload.extend(publication_token.encode("ascii"))
    payload.extend(_prepared_close_proof_text(receipt.channel_id, "receipt.channel_id"))
    payload.extend(_prepared_close_proof_text(receipt.operation_id, "receipt.operation_id"))
    payload.extend(
        _application_admission_text_tuple(
            receipt.operation_ids,
            "receipt.operation_ids",
        )
    )
    snapshot_payload = _application_channel_snapshot_proof_payload(receipt.snapshot)
    payload.extend(struct.pack(">I", len(snapshot_payload)))
    payload.extend(snapshot_payload)
    close_token = receipt.close_token
    if close_token is None:
        payload.extend(b"\0")
    elif type(close_token) is ApplicationChannelCloseToken:
        payload.extend(b"\1")
        payload.extend(_prepared_close_proof_uint(close_token.locator, 32, "receipt.close.locator"))
        payload.extend(
            _prepared_close_proof_uint(close_token.generation, 32, "receipt.close.generation")
        )
    else:
        raise ValueError("application admission receipt close token has an invalid exact type")
    payload.extend(_prepared_close_proof_uint(receipt._registry_token, 64, "receipt.registry"))
    if type(receipt._recoverable) is not bool:
        raise ValueError("receipt.recoverable must be an exact bool")
    payload.extend(b"\1" if receipt._recoverable else b"\0")
    if len(payload) > _MAX_APPLICATION_ADMISSION_PAYLOAD_BYTES:
        raise ValueError("application admission receipt exceeds its aggregate payload bound")
    return bytes(payload)


def _require_application_admission_schema(
    model: type[object],
    expected: tuple[str, ...],
) -> None:
    """Fail import if a signed dataclass grows an unsigned field."""

    actual = tuple(item.name for item in fields(model))
    if actual != expected:
        raise RuntimeError(f"{model.__name__} signed schema changed: {actual!r}")


_require_application_admission_schema(
    ApplicationOperationReservation,
    (
        "operation_id",
        "channel_id",
        "ordinal",
        "started_at",
        "ended_at",
        "initiator_bytes",
        "responder_bytes",
        "parent_operation_id",
    ),
)
_require_application_admission_schema(
    ApplicationChannelBudget,
    ("initiator_bytes", "responder_bytes", "operations"),
)
_require_application_admission_schema(
    ApplicationTransportBinding,
    ("transport_id", "opened_at", "closes_at"),
)
_require_application_admission_schema(
    ApplicationChannelIdentity,
    (
        "channel_id",
        "protocol",
        "owner_id",
        "affinity_digest",
        "binding",
        "opened_at",
        "idle_timeout",
        "hard_deadline",
        "budget",
    ),
)
_require_application_admission_schema(
    ApplicationChannelSnapshot,
    (
        "identity",
        "last_activity_at",
        "idle_deadline",
        "reserved_initiator_bytes",
        "reserved_responder_bytes",
        "reserved_operations",
        "completed_operations",
        "active_operations",
        "closed_at",
        "close_reason",
    ),
)
_require_application_admission_schema(
    ApplicationChannelCloseToken,
    ("locator", "generation"),
)
_require_application_admission_schema(
    ApplicationChannelAdmissionToken,
    (
        "kind",
        "reservation",
        "reservations",
        "identity",
        "replacement_channel_id",
        "replacement_closed_at",
        "replacement_reason",
        "channel_closed_at",
        "channel_close_reason",
        "_registry_token",
        "_reservation_id",
        "_owner_shard_id",
        "_channel_handle",
        "_channel_generation",
        "_expected_snapshot",
        "_prepared_snapshot",
        "_reserved_channel_ids",
        "_reserved_transport_ids",
        "_retain_result_for_recovery",
        "_integrity_token",
    ),
)
_require_application_admission_schema(
    ApplicationChannelAdmissionReceipt,
    (
        "kind",
        "publication_token",
        "channel_id",
        "operation_id",
        "operation_ids",
        "snapshot",
        "close_token",
        "_registry_token",
        "_recoverable",
        "_integrity_token",
    ),
)


def _application_channel_prepared_close_token_payload(token: object) -> bytes:
    """Return an exact framed close-token preimage without dynamic representations."""

    if type(token) is not ApplicationChannelPreparedCloseToken:
        raise ValueError("prepared-close token has an invalid exact type")
    payload = bytearray(b"application-channel-prepared-close-v2\0")
    payload.extend(_prepared_close_proof_text(token.channel_id, "token.channel_id"))
    payload.extend(_prepared_close_proof_datetime(token.closed_at, "token.closed_at"))
    payload.extend(_prepared_close_proof_text(token.reason, "token.reason"))
    payload.extend(_prepared_close_proof_uint(token._registry_token, 64, "token.registry"))
    payload.extend(_prepared_close_proof_uint(token._reservation_id, 64, "token.reservation"))
    payload.extend(_prepared_close_proof_uint(token._owner_shard_id, 32, "token.owner_shard"))
    payload.extend(_prepared_close_proof_uint(token._channel_handle, 32, "token.handle"))
    payload.extend(_prepared_close_proof_uint(token._channel_generation, 32, "token.generation"))
    for snapshot in (token._expected_snapshot, token._prepared_snapshot):
        snapshot_payload = _application_channel_snapshot_proof_payload(snapshot)
        payload.extend(struct.pack(">I", len(snapshot_payload)))
        payload.extend(snapshot_payload)
    if len(payload) > _MAX_PREPARED_CLOSE_PROJECTION_PAYLOAD_BYTES:
        raise ValueError("prepared-close token proof exceeds its payload bound")
    return bytes(payload)


def _application_channel_prepared_close_token_is_authentic(
    authority_secret: bytes,
    token: object,
) -> bool:
    """Fail closed on malformed public tokens without invoking caller callbacks."""

    if type(token) is not ApplicationChannelPreparedCloseToken:
        return False
    try:
        canonical = _application_channel_prepared_close_token_payload(token)
        retained = _prepared_close_proof_digest(token._integrity_token, "token.integrity")
    except (OverflowError, ValueError):
        return False
    expected = hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(retained, expected)


def _application_channel_prepared_close_integrity_token(
    authority_secret: bytes,
    token: ApplicationChannelPreparedCloseToken,
) -> str:
    """Authenticate every public and routing field of one close reservation."""

    canonical = _application_channel_prepared_close_token_payload(token)
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class ApplicationChannelPreparedCloseProjection:
    """Detached authenticated precommit and projected terminal close truth."""

    publication_token: str
    channel_id: str
    owner_id: str
    protocol: str
    affinity_digest: str
    transport_id: str
    owner_partition_id: int
    channel_handle: int
    channel_generation: int
    expected_current: ApplicationChannelSnapshot
    projected_terminal: ApplicationChannelSnapshot
    cumulative_initiator_bytes: int
    cumulative_responder_bytes: int
    cumulative_operations: int
    completed_operations: int
    active_operations: int
    closed_at: datetime
    close_reason: str
    _registry_token: int = field(repr=False, default=0)
    _reservation_id: int = field(repr=False, default=0)
    _prepared_token_id: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")

    @property
    def proof_token(self) -> str:
        """Return the opaque keyed proof over this exact retained projection."""

        return self._integrity_token


@dataclass(frozen=True, slots=True)
class _ApplicationChannelPreparedCloseProjectionAuthority:
    """Private intact preimage and exact public proof retained in one charged slot."""

    token_id: int
    reservation_id: int
    integrity_token: str
    public_projection: ApplicationChannelPreparedCloseProjection
    trusted_projection: ApplicationChannelPreparedCloseProjection


def _application_channel_prepared_close_projection_payload(projection: object) -> bytes:
    """Return the fixed-shape authenticated preimage of one public projection."""

    if type(projection) is not ApplicationChannelPreparedCloseProjection:
        raise ValueError("prepared-close projection has an invalid exact type")
    payload = bytearray(b"application-channel-prepared-close-projection-v1\0")
    payload.extend(
        _prepared_close_proof_text(projection.publication_token, "projection.publication_token")
    )
    payload.extend(_prepared_close_proof_text(projection.channel_id, "projection.channel_id"))
    payload.extend(_prepared_close_proof_text(projection.owner_id, "projection.owner_id"))
    payload.extend(_prepared_close_proof_text(projection.protocol, "projection.protocol"))
    payload.extend(
        _prepared_close_proof_text(
            projection.affinity_digest,
            "projection.affinity_digest",
        )
    )
    payload.extend(_prepared_close_proof_text(projection.transport_id, "projection.transport_id"))
    payload.extend(
        _prepared_close_proof_uint(
            projection.owner_partition_id,
            32,
            "projection.owner_partition_id",
        )
    )
    payload.extend(
        _prepared_close_proof_uint(projection.channel_handle, 32, "projection.channel_handle")
    )
    payload.extend(
        _prepared_close_proof_uint(
            projection.channel_generation,
            32,
            "projection.channel_generation",
        )
    )
    for snapshot in (projection.expected_current, projection.projected_terminal):
        snapshot_payload = _application_channel_snapshot_proof_payload(snapshot)
        payload.extend(struct.pack(">I", len(snapshot_payload)))
        payload.extend(snapshot_payload)
    payload.extend(
        _prepared_close_proof_uint(
            projection.cumulative_initiator_bytes,
            64,
            "projection.cumulative_initiator_bytes",
        )
    )
    payload.extend(
        _prepared_close_proof_uint(
            projection.cumulative_responder_bytes,
            64,
            "projection.cumulative_responder_bytes",
        )
    )
    payload.extend(
        _prepared_close_proof_uint(
            projection.cumulative_operations,
            32,
            "projection.cumulative_operations",
        )
    )
    payload.extend(
        _prepared_close_proof_uint(
            projection.completed_operations,
            32,
            "projection.completed_operations",
        )
    )
    payload.extend(
        _prepared_close_proof_uint(
            projection.active_operations,
            32,
            "projection.active_operations",
        )
    )
    payload.extend(_prepared_close_proof_datetime(projection.closed_at, "projection.closed_at"))
    payload.extend(_prepared_close_proof_text(projection.close_reason, "projection.close_reason"))
    payload.extend(
        _prepared_close_proof_uint(projection._registry_token, 64, "projection.registry")
    )
    payload.extend(
        _prepared_close_proof_uint(projection._reservation_id, 64, "projection.reservation")
    )
    payload.extend(
        _prepared_close_proof_uint(
            projection._prepared_token_id,
            64,
            "projection.prepared_token_id",
        )
    )
    if len(payload) > _MAX_PREPARED_CLOSE_PROJECTION_PAYLOAD_BYTES:
        raise ValueError("prepared-close projection proof exceeds its payload bound")
    return bytes(payload)


def _application_channel_prepared_close_projection_integrity_token(
    authority_secret: bytes,
    projection: ApplicationChannelPreparedCloseProjection,
) -> str:
    """Authenticate the exact detached proof and its capability locator."""

    canonical = _application_channel_prepared_close_projection_payload(projection)
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


def _application_channel_prepared_close_projection_is_authentic(
    authority_secret: bytes,
    projection: object,
) -> bool:
    """Fail closed on malformed public projections before dynamic operations."""

    if type(projection) is not ApplicationChannelPreparedCloseProjection:
        return False
    try:
        canonical = _application_channel_prepared_close_projection_payload(projection)
        retained = _prepared_close_proof_digest(
            projection._integrity_token,
            "projection.integrity",
        )
    except (OverflowError, ValueError):
        return False
    expected = hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(retained, expected)


def _prepared_close_projection_matches_token(
    token: ApplicationChannelPreparedCloseToken,
    projection: ApplicationChannelPreparedCloseProjection,
) -> bool:
    """Validate every duplicated public scalar against both exact snapshots and token."""

    try:
        token_expected = _application_channel_snapshot_proof_payload(token._expected_snapshot)
        token_terminal = _application_channel_snapshot_proof_payload(token._prepared_snapshot)
        proof_expected = _application_channel_snapshot_proof_payload(projection.expected_current)
        proof_terminal = _application_channel_snapshot_proof_payload(projection.projected_terminal)
        expected_identity = _application_channel_identity_proof_payload(
            projection.expected_current.identity
        )
        terminal_identity = _application_channel_identity_proof_payload(
            projection.projected_terminal.identity
        )
    except (OverflowError, ValueError):
        return False
    expected = projection.expected_current
    terminal = projection.projected_terminal
    expected_identity_value = expected.identity
    expected_binding = expected_identity_value.binding
    return (
        token_expected == proof_expected
        and token_terminal == proof_terminal
        and expected_identity == terminal_identity
        and projection.publication_token == token.publication_token
        and projection._registry_token == token._registry_token
        and projection._reservation_id == token._reservation_id
        and projection._prepared_token_id == id(token)
        and projection.owner_partition_id == token._owner_shard_id
        and projection.channel_handle == token._channel_handle
        and projection.channel_generation == token._channel_generation
        and projection.channel_id == token.channel_id
        and projection.channel_id == expected.channel_id
        and projection.channel_id == terminal.channel_id
        and projection.owner_id == expected_identity_value.owner_id
        and projection.owner_id == terminal.identity.owner_id
        and projection.protocol == expected_identity_value.protocol
        and projection.protocol == terminal.identity.protocol
        and projection.affinity_digest == expected_identity_value.affinity_digest
        and projection.affinity_digest == terminal.identity.affinity_digest
        and projection.transport_id == expected_binding.transport_id
        and projection.transport_id == terminal.identity.binding.transport_id
        and projection.cumulative_initiator_bytes == expected.reserved_initiator_bytes
        and projection.cumulative_initiator_bytes == terminal.reserved_initiator_bytes
        and projection.cumulative_responder_bytes == expected.reserved_responder_bytes
        and projection.cumulative_responder_bytes == terminal.reserved_responder_bytes
        and projection.cumulative_operations == expected.reserved_operations
        and projection.cumulative_operations == terminal.reserved_operations
        and projection.completed_operations == expected.completed_operations
        and projection.completed_operations == terminal.completed_operations
        and projection.active_operations == expected.active_operations
        and projection.active_operations == terminal.active_operations
        and projection.active_operations == 0
        and expected.last_activity_at == terminal.last_activity_at
        and expected.idle_deadline == terminal.idle_deadline
        and expected.closed_at is None
        and expected.close_reason == ""
        and projection.closed_at == token.closed_at
        and projection.closed_at == terminal.closed_at
        and projection.close_reason == token.reason
        and projection.close_reason == terminal.close_reason
    )


def _detached_prepared_close_text(value: str) -> str:
    """Create an independent immutable text value from one validated proof scalar."""

    return value.encode("utf-8").decode("utf-8")


def _detached_prepared_close_datetime(value: datetime) -> datetime:
    """Create an independent exact UTC datetime value."""

    return _datetime_from_us(_datetime_us(value))


def _detached_application_channel_snapshot(
    snapshot: ApplicationChannelSnapshot,
) -> ApplicationChannelSnapshot:
    """Reconstruct a deeply detached snapshot after exact bounded-shape validation."""

    _application_channel_snapshot_proof_payload(snapshot)
    identity = snapshot.identity
    binding = identity.binding
    budget = identity.budget
    detached_binding = ApplicationTransportBinding(
        transport_id=_detached_prepared_close_text(binding.transport_id),
        opened_at=_detached_prepared_close_datetime(binding.opened_at),
        closes_at=_detached_prepared_close_datetime(binding.closes_at),
    )
    detached_budget = ApplicationChannelBudget(
        initiator_bytes=budget.initiator_bytes,
        responder_bytes=budget.responder_bytes,
        operations=budget.operations,
    )
    detached_identity = ApplicationChannelIdentity(
        channel_id=_detached_prepared_close_text(identity.channel_id),
        protocol=_detached_prepared_close_text(identity.protocol),
        owner_id=_detached_prepared_close_text(identity.owner_id),
        affinity_digest=_detached_prepared_close_text(identity.affinity_digest),
        binding=detached_binding,
        opened_at=_detached_prepared_close_datetime(identity.opened_at),
        idle_timeout=timedelta(
            days=identity.idle_timeout.days,
            seconds=identity.idle_timeout.seconds,
            microseconds=identity.idle_timeout.microseconds,
        ),
        hard_deadline=_detached_prepared_close_datetime(identity.hard_deadline),
        budget=detached_budget,
    )
    return ApplicationChannelSnapshot(
        identity=detached_identity,
        last_activity_at=_detached_prepared_close_datetime(snapshot.last_activity_at),
        idle_deadline=_detached_prepared_close_datetime(snapshot.idle_deadline),
        reserved_initiator_bytes=snapshot.reserved_initiator_bytes,
        reserved_responder_bytes=snapshot.reserved_responder_bytes,
        reserved_operations=snapshot.reserved_operations,
        completed_operations=snapshot.completed_operations,
        active_operations=snapshot.active_operations,
        closed_at=(
            _detached_prepared_close_datetime(snapshot.closed_at)
            if snapshot.closed_at is not None
            else None
        ),
        close_reason=_detached_prepared_close_text(snapshot.close_reason),
    )


def _detached_prepared_close_projection(
    projection: ApplicationChannelPreparedCloseProjection,
) -> ApplicationChannelPreparedCloseProjection:
    """Reconstruct the private proof preimage without retaining public mutable aliases."""

    _application_channel_prepared_close_projection_payload(projection)
    return ApplicationChannelPreparedCloseProjection(
        publication_token=_detached_prepared_close_text(projection.publication_token),
        channel_id=_detached_prepared_close_text(projection.channel_id),
        owner_id=_detached_prepared_close_text(projection.owner_id),
        protocol=_detached_prepared_close_text(projection.protocol),
        affinity_digest=_detached_prepared_close_text(projection.affinity_digest),
        transport_id=_detached_prepared_close_text(projection.transport_id),
        owner_partition_id=projection.owner_partition_id,
        channel_handle=projection.channel_handle,
        channel_generation=projection.channel_generation,
        expected_current=_detached_application_channel_snapshot(projection.expected_current),
        projected_terminal=_detached_application_channel_snapshot(projection.projected_terminal),
        cumulative_initiator_bytes=projection.cumulative_initiator_bytes,
        cumulative_responder_bytes=projection.cumulative_responder_bytes,
        cumulative_operations=projection.cumulative_operations,
        completed_operations=projection.completed_operations,
        active_operations=projection.active_operations,
        closed_at=_detached_prepared_close_datetime(projection.closed_at),
        close_reason=_detached_prepared_close_text(projection.close_reason),
        _registry_token=projection._registry_token,
        _reservation_id=projection._reservation_id,
        _prepared_token_id=projection._prepared_token_id,
        _integrity_token=_detached_prepared_close_text(projection._integrity_token),
    )


@dataclass(frozen=True, slots=True)
class _ApplicationChannelPreparedCloseCapability:
    """Registry-owned trusted preimage for one exact close reservation."""

    token_id: int
    reservation_id: int
    integrity_token: str
    trusted_token: ApplicationChannelPreparedCloseToken
    projection_authority: _ApplicationChannelPreparedCloseProjectionAuthority


@dataclass(slots=True)
class _ApplicationChannelCommitJournal:
    """Private retry state for one recoverable open or completed operation."""

    reservation_id: int
    insert_attempted: bool = False
    channel_handle: int | None = None
    channel_generation: int | None = None
    initial_affinity_size: int | None = None
    accounting_applied: bool = False


@dataclass(slots=True)
class _ApplicationChannelCloseCommitJournal:
    """Private retry state for one recoverable close-only mutation."""

    reservation_id: int
    accounting_applied: bool = False


@dataclass(frozen=True, slots=True)
class ApplicationChannelCloseAdmissionReceipt:
    """Exact authenticated proof of one committed close-only mutation."""

    publication_token: str
    channel_id: str
    snapshot: ApplicationChannelSnapshot
    close: ApplicationChannelCloseResult
    _registry_token: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")


def _application_channel_close_receipt_integrity_token(
    authority_secret: bytes,
    receipt: ApplicationChannelCloseAdmissionReceipt,
) -> str:
    """Authenticate one close receipt and its exact committed snapshot."""

    canonical = repr(
        (
            "application-channel-close-receipt-v1",
            receipt.publication_token,
            receipt.channel_id,
            receipt.snapshot,
            receipt.close,
            receipt._registry_token,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class ApplicationChannelCloseAdmissionResult:
    """Frozen result of one prepared close-only admission."""

    snapshot: ApplicationChannelSnapshot
    close: ApplicationChannelCloseResult
    receipt: ApplicationChannelCloseAdmissionReceipt


@dataclass(frozen=True, slots=True)
class _RecoverableApplicationCloseResult:
    """Exact retained close result awaiting outer acknowledgement."""

    token: ApplicationChannelPreparedCloseToken
    result: ApplicationChannelCloseAdmissionResult
    projection_authority: _ApplicationChannelPreparedCloseProjectionAuthority


@dataclass(frozen=True, slots=True)
class ApplicationChannelCloseCommitRecovery:
    """Reconciliation of an exception during one close-only commit."""

    status: Literal["committed", "not_committed", "indeterminate"]
    result: ApplicationChannelCloseAdmissionResult | None = None


class ApplicationChannelPreparedCommit:
    """No-fail channel commit capability valid inside its claim context."""

    __slots__ = (
        "_active",
        "_committed",
        "_recovery_status",
        "_registry",
        "_result",
        "_token",
    )

    def __init__(
        self,
        registry: ApplicationChannelRegistry,
        token: ApplicationChannelAdmissionToken,
    ) -> None:
        self._registry = registry
        self._token = token
        self._active = True
        self._committed = False
        self._recovery_status: Literal["none", "committed", "not_committed", "indeterminate"] = (
            "none"
        )
        self._result: ApplicationChannelAdmissionResult | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact claim has committed."""

        return self._committed

    @property
    def result(self) -> ApplicationChannelAdmissionResult | None:
        """Return the committed result, if any."""

        return self._result

    @property
    def recovery_status(
        self,
    ) -> Literal["none", "committed", "not_committed", "indeterminate"]:
        """Return the certified outcome after an exceptional commit attempt."""

        return self._recovery_status

    def commit_no_fail(self) -> ApplicationChannelAdmissionResult:
        """Publish the already-validated mutation as the final transaction step."""

        if not self._active:
            raise StateError("application channel prepared commit is no longer active")
        if self._committed:
            raise StateError("application channel prepared admission was already committed")
        try:
            self._result = self._registry._commit_claimed_admission(self._token)
        except BaseException as primary_error:
            self._recovery_status = "indeterminate"
            try:
                recovery = self._registry._reconcile_claimed_admission(self._token)
            except BaseException as recovery_error:
                primary_error.add_note(
                    f"application admission recovery also failed: {recovery_error!r}"
                )
            else:
                self._recovery_status = recovery.status
                if recovery.status == "committed":
                    assert recovery.result is not None
                    self._result = recovery.result
                    self._committed = True
                    return self._result
            raise
        self._committed = True
        return self._result

    def commit(self) -> ApplicationChannelAdmissionResult:
        """Compatibility alias for :meth:`commit_no_fail`."""

        return self.commit_no_fail()

    def _close(self) -> None:
        self._active = False


class ApplicationChannelPreparedCloseCommit:
    """No-fail close commit capability valid only inside its exact claim."""

    __slots__ = (
        "_active",
        "_committed",
        "_recovery_status",
        "_registry",
        "_result",
        "_token",
    )

    def __init__(
        self,
        registry: ApplicationChannelRegistry,
        token: ApplicationChannelPreparedCloseToken,
    ) -> None:
        self._registry = registry
        self._token = token
        self._active = True
        self._committed = False
        self._recovery_status: Literal["none", "committed", "not_committed", "indeterminate"] = (
            "none"
        )
        self._result: ApplicationChannelCloseAdmissionResult | None = None

    @property
    def committed(self) -> bool:
        """Return whether canonical close truth committed despite any lost return."""

        return self._committed

    @property
    def result(self) -> ApplicationChannelCloseAdmissionResult | None:
        """Return the exact committed result when known."""

        return self._result

    @property
    def recovery_status(
        self,
    ) -> Literal["none", "committed", "not_committed", "indeterminate"]:
        """Return the certified outcome after an exceptional close attempt."""

        return self._recovery_status

    def commit_no_fail(self) -> ApplicationChannelCloseAdmissionResult:
        """Publish the prevalidated close mutation exactly once."""

        if not self._active:
            raise StateError("application channel prepared close is no longer active")
        if self._committed:
            raise StateError("application channel prepared close was already committed")
        try:
            self._result = self._registry._commit_claimed_close(self._token)
        except BaseException as primary_error:
            self._recovery_status = "indeterminate"
            try:
                recovery = self._registry._reconcile_claimed_close(self._token)
            except BaseException as recovery_error:
                primary_error.add_note(
                    f"application close recovery also failed: {recovery_error!r}"
                )
            else:
                self._recovery_status = recovery.status
                if recovery.status == "committed":
                    assert recovery.result is not None
                    self._result = recovery.result
                    self._committed = True
                    return self._result
            raise
        self._committed = True
        return self._result

    def commit(self) -> ApplicationChannelCloseAdmissionResult:
        """Compatibility alias for :meth:`commit_no_fail`."""

        return self.commit_no_fail()

    def _close(self) -> None:
        self._active = False


class ApplicationChannelPageCursor:
    """Opaque mutation-fenced cursor for one exact owner bucket."""

    __slots__ = (
        "_after_handle",
        "_mutation_version",
        "_owner_id",
        "_registry_token",
        "_shard_id",
    )

    def __init__(
        self,
        *,
        registry_token: int,
        owner_id: str,
        shard_id: int,
        mutation_version: int,
        after_handle: int,
    ) -> None:
        self._registry_token = registry_token
        self._owner_id = owner_id
        self._shard_id = shard_id
        self._mutation_version = mutation_version
        self._after_handle = after_handle


class _MutationGate:
    """Allow concurrent mutations while giving watermarks exclusive admission."""

    def __init__(self) -> None:
        self._condition = Condition(Lock())
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    def enter_mutation(self) -> None:
        """Enter the shared mutation lane without allocating a context wrapper."""

        with self._condition:
            while self._writer or self._waiting_writers:
                self._condition.wait()
            self._readers += 1

    def exit_mutation(self) -> None:
        """Leave one shared mutation lane entered by :meth:`enter_mutation`."""

        with self._condition:
            self._readers -= 1
            if self._readers == 0:
                self._condition.notify_all()

    @contextmanager
    def mutation(self) -> Iterator[None]:
        """Enter the shared mutation lane without serializing other owners."""

        self.enter_mutation()
        try:
            yield
        finally:
            self.exit_mutation()

    @contextmanager
    def watermark(self) -> Iterator[None]:
        """Enter the exclusive watermark lane after active mutations finish."""

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


@dataclass(frozen=True, slots=True)
class _ApplicationChannelShardAccounting:
    """Atomically replaceable shard counters plus prepared-commit markers."""

    open_channels: int = 0
    maximum_affinity_bucket: int = 0
    high_water_mark: int = 0
    mutation_version: int = 0
    estimated_value_bytes: int = 0
    prepared_commit_ids: frozenset[int] = frozenset()


@dataclass(slots=True)
class _ApplicationChannelShard:
    """All current state owned by one stable owner partition."""

    shard_id: int
    lock: RLock = field(default_factory=RLock)
    channels: _PackedChannelStore = field(default_factory=_PackedChannelStore)
    operations: CompactIndexedStore[str, ApplicationOperationReservation] = field(
        default_factory=lambda: CompactIndexedStore(
            channel=lambda item: item.channel_id,
            parent=lambda item: item.parent_operation_id,
        )
    )
    used_operation_ids: _PackedUsedOperationIds = field(default_factory=_PackedUsedOperationIds)
    active_expiry: PackedHandleExpiryIndex = field(default_factory=PackedHandleExpiryIndex)
    closed_expiry: PackedHandleExpiryIndex = field(default_factory=PackedHandleExpiryIndex)
    operation_blocker_expiry: PackedHandleExpiryIndex = field(
        default_factory=PackedHandleExpiryIndex
    )
    _accounting: _ApplicationChannelShardAccounting = field(
        default_factory=_ApplicationChannelShardAccounting
    )
    lookup_candidates_inspected: int = 0
    operation_deletions: int = 0
    used_id_deletions: int = 0
    compaction_cursor: int = 0
    expiry_compaction_cursor: int = 0

    @property
    def open_channels(self) -> int:
        return self._accounting.open_channels

    @open_channels.setter
    def open_channels(self, value: int) -> None:
        self._accounting = replace(self._accounting, open_channels=value)

    @property
    def maximum_affinity_bucket(self) -> int:
        return self._accounting.maximum_affinity_bucket

    @maximum_affinity_bucket.setter
    def maximum_affinity_bucket(self, value: int) -> None:
        self._accounting = replace(self._accounting, maximum_affinity_bucket=value)

    @property
    def high_water_mark(self) -> int:
        return self._accounting.high_water_mark

    @high_water_mark.setter
    def high_water_mark(self, value: int) -> None:
        self._accounting = replace(self._accounting, high_water_mark=value)

    @property
    def mutation_version(self) -> int:
        return self._accounting.mutation_version

    @mutation_version.setter
    def mutation_version(self, value: int) -> None:
        self._accounting = replace(self._accounting, mutation_version=value)

    @property
    def estimated_value_bytes(self) -> int:
        return self._accounting.estimated_value_bytes

    @estimated_value_bytes.setter
    def estimated_value_bytes(self, value: int) -> None:
        self._accounting = replace(self._accounting, estimated_value_bytes=value)


@dataclass(slots=True)
class _RoutePartition:
    """Lazy exact semantic-ID routes into owner shards."""

    partition_id: int
    lock: RLock = field(default_factory=RLock)
    channels: PackedUniqueDigestMap = field(
        default_factory=lambda: PackedUniqueDigestMap(b"ef-route-chan")
    )
    transports: PackedUniqueDigestMap = field(
        default_factory=lambda: PackedUniqueDigestMap(b"ef-route-trans")
    )
    operations: IncrementalExactMap[str, int] = field(default_factory=IncrementalExactMap)
    channel_deletions: int = 0
    transport_deletions: int = 0
    operation_deletions: int = 0
    compaction_cursor: int = 0

    def compact_primary(self, max_work: int) -> int:
        """Advance deletion-triggered primary-map rotations within a fixed budget."""

        if max_work <= 0:
            return 0
        stores = (
            (self.channels, "channel_deletions"),
            (self.transports, "transport_deletions"),
            (self.operations, "operation_deletions"),
        )
        work = 0
        visited = 0
        while visited < len(stores) and work < max_work:
            position = self.compaction_cursor % len(stores)
            store, deletion_field = stores[position]
            visited += 1
            metrics = store.metrics()
            deletions = getattr(self, deletion_field)
            if not deletions and not metrics.primary_compaction_pending:
                self.compaction_cursor = (position + 1) % len(stores)
                continue
            inspected = store.compact_primary(
                max_entries=max_work - work,
                force=(
                    not metrics.primary_compaction_pending
                    and bool(deletions)
                    and metrics.live_entries == 0
                ),
            )
            work += inspected
            pending = store.metrics().primary_compaction_pending
            if not pending:
                setattr(self, deletion_field, 0)
                self.compaction_cursor = (position + 1) % len(stores)
            else:
                self.compaction_cursor = position
                break
        return work

    def primary_metrics(self) -> tuple[IndexMetrics, IndexMetrics, IndexMetrics]:
        """Return the three route-store structural metrics."""

        return (
            self.channels.metrics(estimate_bytes=True),
            self.transports.metrics(estimate_bytes=True),
            self.operations.metrics(estimate_bytes=True),
        )


def _stable_partition(namespace: str, value: str, partition_count: int) -> int:
    material = f"{namespace}\0{value}".encode()
    digest = hashlib.blake2b(material, digest_size=8).digest()
    return int.from_bytes(digest, "big") % partition_count


def _canonical_route_digest(value: str) -> int | None:
    """Return the exact 64-bit token or packed prefix of a canonical semantic ID."""

    _prefix, separator, suffix = value.rpartition("-")
    if not separator or len(suffix) not in {16, 32}:
        return None
    try:
        return int(suffix[:16], 16)
    except ValueError:
        return None


def _snapshot_estimated_bytes(snapshot: ApplicationChannelSnapshot) -> int:
    """Return the packed retained-value estimate for one channel row."""

    identity = snapshot.identity
    binding = identity.binding
    encoded_lengths = tuple(
        len(value.encode("utf-8"))
        for value in (
            identity.channel_id,
            identity.protocol,
            identity.owner_id,
            identity.affinity_digest,
            binding.transport_id,
        )
    )
    return (
        _PACKED_CHANNEL_NUMERIC_BYTES
        + sum(encoded_lengths)
        + sum(max(1, (length.bit_length() + 6) // 7) for length in encoded_lengths)
        + 3 * array("I").itemsize
    )


def _decoded_snapshot_estimated_bytes(snapshot: ApplicationChannelSnapshot) -> int:
    """Return shallow exact bytes retained only by one decoded cache view."""

    identity = snapshot.identity
    binding = identity.binding
    budget = identity.budget
    values: tuple[object, ...] = (
        snapshot,
        identity,
        binding,
        budget,
        identity.channel_id,
        identity.protocol,
        identity.owner_id,
        identity.affinity_digest,
        binding.transport_id,
        binding.opened_at,
        binding.closes_at,
        identity.opened_at,
        identity.idle_timeout,
        identity.hard_deadline,
        snapshot.last_activity_at,
        snapshot.idle_deadline,
        snapshot.closed_at,
        snapshot.close_reason,
    )
    unique = {id(value): value for value in values}
    return sum(sys.getsizeof(value) for value in unique.values())


def _prepared_close_projection_authority_estimated_bytes(
    authority: _ApplicationChannelPreparedCloseProjectionAuthority,
) -> int:
    """Return a conservative estimate for one charged public/private proof pair."""

    trusted = authority.trusted_projection
    proof_values: tuple[object, ...] = (
        trusted,
        trusted.publication_token,
        trusted.channel_id,
        trusted.owner_id,
        trusted.protocol,
        trusted.affinity_digest,
        trusted.transport_id,
        trusted.closed_at,
        trusted.close_reason,
        trusted._integrity_token,
    )
    unique = {id(value): value for value in proof_values}
    return (
        sys.getsizeof(authority)
        + sys.getsizeof(authority.integrity_token)
        + 2 * sum(sys.getsizeof(value) for value in unique.values())
        + 2 * _decoded_snapshot_estimated_bytes(trusted.expected_current)
        + 2 * _decoded_snapshot_estimated_bytes(trusted.projected_terminal)
    )


def _operation_estimated_bytes(operation: ApplicationOperationReservation) -> int:
    """Return a shallow, length-aware estimate for one active operation."""

    return sum(
        sys.getsizeof(value)
        for value in (
            operation,
            operation.operation_id,
            operation.channel_id,
            operation.parent_operation_id,
            operation.started_at,
            operation.ended_at,
        )
    )


def _used_id_estimated_bytes(key: tuple[int, str]) -> int:
    """Return the retained memory estimate for one compact used-ID marker."""

    row_bytes = _PackedUsedOperationIds._HEADER.size + len(key[1].encode("utf-8"))
    return _PACKED_USED_ID_INLINE_BYTES + (
        sys.getsizeof(b"") + row_bytes if row_bytes > _PACKED_USED_ID_INLINE_BYTES else 0
    )


@contextmanager
def _acquire_stable_locks(entries: list[tuple[tuple[int, int], RLock]]) -> Iterator[None]:
    """Acquire distinct locks in stable route-before-owner shard order."""

    unique: dict[int, tuple[tuple[int, int], RLock]] = {}
    for token, lock in entries:
        unique.setdefault(id(lock), (token, lock))
    ordered = sorted(unique.values(), key=lambda item: item[0])
    for _token, lock in ordered:
        lock.acquire()
    try:
        yield
    finally:
        for _token, lock in reversed(ordered):
            lock.release()


class _OpenLockSet:
    """Allocation-light context for one fixed fresh-open lock set."""

    __slots__ = ("_routes", "_shard")

    def __init__(
        self,
        channel_route: _RoutePartition,
        transport_route: _RoutePartition,
        operation_route: _RoutePartition | None,
        shard: _ApplicationChannelShard,
    ) -> None:
        routes = [channel_route]
        if transport_route is not channel_route:
            routes.append(transport_route)
        if operation_route is not None and all(operation_route is not route for route in routes):
            routes.append(operation_route)
        routes.sort(key=lambda route: route.partition_id)
        self._routes = routes
        self._shard = shard

    def __enter__(self) -> None:
        for route in self._routes:
            route.lock.acquire()
        self._shard.lock.acquire()

    def __exit__(self, *_error: object) -> None:
        self._shard.lock.release()
        for route in reversed(self._routes):
            route.lock.release()


def _acquire_open_locks(
    channel_route: _RoutePartition,
    transport_route: _RoutePartition,
    operation_route: _RoutePartition | None,
    shard: _ApplicationChannelShard,
) -> _OpenLockSet:
    """Return the fixed fresh-open route set ordered before its owner shard."""

    return _OpenLockSet(channel_route, transport_route, operation_route, shard)


class ApplicationChannelRegistry:
    """Shared current-state registry for persistent application protocols.

    Owners map to lazy deterministic shards. Cross-key mutations acquire route
    partitions before owner shards in stable numeric order. Exact reads never
    acquire a registry-global mutation lock, and frozen snapshots never escape
    while a shard lock is held by consumer code.
    """

    def __init__(
        self,
        *,
        window_start: datetime,
        window_end: datetime,
        closed_grace: timedelta = _DEFAULT_CLOSED_GRACE,
        max_reusable_per_affinity: int = _DEFAULT_MAX_REUSABLE_PER_AFFINITY,
        shard_count: int = _DEFAULT_SHARD_COUNT,
    ) -> None:
        """Create an empty registry fenced to one canonical generation window."""

        self._window_start = ensure_utc(window_start)
        self._window_end = ensure_utc(window_end)
        if self._window_end < self._window_start:
            raise ValueError("Application channel window_end cannot precede window_start")
        if closed_grace < timedelta(0):
            raise ValueError("Application channel closed_grace must be non-negative")
        if max_reusable_per_affinity <= 0:
            raise ValueError("max_reusable_per_affinity must be positive")
        if shard_count <= 0:
            raise ValueError("Application channel shard_count must be positive")
        self._closed_grace = closed_grace
        self._max_reusable_per_affinity = max_reusable_per_affinity
        self._shard_count = shard_count
        self._shards: dict[int, _ApplicationChannelShard] = {}
        # The tiny directory has one pointer per stable route partition while
        # the materially larger partition objects and maps remain lazy.  Empty
        # slots can therefore be reclaimed without retaining dict capacity for
        # every semantic ID observed over a long scenario.
        self._route_partitions: list[_RoutePartition | None] = [None] * shard_count
        self._directory_lock = RLock()
        self._gate = _MutationGate()
        self._watermark = self._window_start
        self._watermark_lane = Lock()
        self._route_compaction_cursor = 0
        self._route_reclaim_cursor = 0
        self._retired_route_compaction_rotations = 0
        self._retired_route_compaction_work = 0
        self._retired_route_compaction_seconds = 0.0
        self._shard_compaction_cursor = 0
        self._expiry_compaction_cursor = 0
        self._prepared_lock = RLock()
        self._admission_secret = secrets.token_bytes(32)
        self._next_prepared_reservation_id = 1
        self._prepared_reservations: dict[int, ApplicationChannelAdmissionToken] = {}
        self._prepared_capabilities: dict[int, _ApplicationChannelAdmissionCapability] = {}
        self._claimed_reservations: set[int] = set()
        self._prepared_channel_ids: dict[str, int] = {}
        self._prepared_transport_ids: dict[str, int] = {}
        self._prepared_operation_ids: dict[str, int] = {}
        # Keep exact reservation membership rather than only aggregate counts.
        # Release is deliberately retryable after an injected tail failure, so
        # decrementing an anonymous count could otherwise double-release a
        # sibling preparation that shares this affinity.
        self._prepared_affinity_reservations: dict[tuple[str, str], set[int]] = {}
        self._prepared_close_tokens: dict[int, ApplicationChannelPreparedCloseToken] = {}
        self._prepared_close_capabilities: dict[
            int,
            _ApplicationChannelPreparedCloseCapability,
        ] = {}
        self._recoverable_admission_results: dict[
            int,
            _RecoverableApplicationAdmissionResult,
        ] = {}
        self._recoverable_admission_receipts: dict[
            int,
            ApplicationChannelAdmissionReceipt,
        ] = {}
        self._recoverable_admission_slots: set[int] = set()
        self._recoverable_close_results: dict[int, _RecoverableApplicationCloseResult] = {}
        self._recoverable_close_receipts: dict[
            int,
            ApplicationChannelCloseAdmissionReceipt,
        ] = {}
        self._acknowledging_admission_results: dict[
            int,
            _RecoverableApplicationAdmissionResult,
        ] = {}
        self._acknowledging_close_results: dict[
            int,
            _RecoverableApplicationCloseResult,
        ] = {}
        self._prepared_commit_journals: dict[int, _ApplicationChannelCommitJournal] = {}
        self._prepared_close_commit_journals: dict[
            int,
            _ApplicationChannelCloseCommitJournal,
        ] = {}
        self._releasing_reservations: set[int] = set()
        # Ordinary public mutations publish only short-lived exact-key claims
        # while they run.  The claims let preparation detect an in-flight
        # conflicting mutation without retaining this registry-wide metadata
        # lock across owner/route locks, so disjoint owners still progress.
        self._mutating_channel_ids: dict[str, int] = {}
        self._mutating_transport_ids: dict[str, int] = {}
        self._mutating_operation_ids: dict[str, int] = {}
        self._mutating_affinity_counts: dict[tuple[str, str], int] = {}

    def _owner_shard_id(self, owner_id: str) -> int:
        return _stable_partition("owner", owner_id, self._shard_count)

    @property
    def shard_count(self) -> int:
        """Return the fixed owner/route partition count."""

        return self._shard_count

    @property
    def window_start(self) -> datetime:
        """Return the inclusive canonical generation-window start."""

        return self._window_start

    @property
    def window_end(self) -> datetime:
        """Return the exclusive canonical generation-window end."""

        return self._window_end

    def owner_partition_id(self, owner_id: str) -> int:
        """Return the stable owner partition used by protocol sidecars."""

        if not owner_id.strip():
            raise ValueError("Application channel owner_id must not be empty")
        return self._owner_shard_id(owner_id)

    def _retirement_proof_for_snapshot(
        self,
        snapshot: ApplicationChannelSnapshot,
    ) -> ApplicationChannelRetirementProof:
        """Issue one stateless proof for an exact terminal registry snapshot."""

        if (
            type(snapshot) is not ApplicationChannelSnapshot
            or snapshot.closed_at is None
            or not snapshot.close_reason
        ):
            raise StateError("Application retirement proof requires a terminal snapshot")
        placeholder = ApplicationChannelRetirementProof(
            snapshot=snapshot,
            _registry_token=id(self),
        )
        return replace(
            placeholder,
            _integrity_token=_application_channel_retirement_proof_integrity_token(
                self._admission_secret,
                placeholder,
            ),
        )

    def retirement_proof(self, channel_id: str) -> ApplicationChannelRetirementProof:
        """Return authenticated terminal truth while its registry row is retained."""

        snapshot = self.get(channel_id)
        if snapshot is None:
            raise StateError(f"Application channel {channel_id!r} has no retained terminal row")
        return self._retirement_proof_for_snapshot(snapshot)

    def authenticates_retirement_proof(self, proof: object) -> bool:
        """Authenticate terminal truth without consulting a possibly expired row."""

        if type(proof) is not ApplicationChannelRetirementProof:
            return False
        try:
            if (
                proof._registry_token != id(self)
                or type(proof.snapshot) is not ApplicationChannelSnapshot
                or proof.snapshot.closed_at is None
                or not proof.snapshot.close_reason
            ):
                return False
            expected = _application_channel_retirement_proof_integrity_token(
                self._admission_secret,
                proof,
            )
            retained = _prepared_close_proof_digest(
                proof._integrity_token,
                "retirement.integrity",
            )
        except (AttributeError, TypeError, ValueError):
            return False
        return hmac.compare_digest(retained, expected)

    def authenticates_admission_token(self, token: ApplicationChannelAdmissionToken) -> bool:
        """Return whether one intact token is currently active in this registry."""

        if type(token) is not ApplicationChannelAdmissionToken:
            return False
        with self._prepared_lock:
            try:
                self._active_prepared_admission_locked(token)
            except StateError:
                return False
            return True

    def authenticates_admission_receipt(
        self,
        receipt: ApplicationChannelAdmissionReceipt,
    ) -> bool:
        """Return whether this registry issued the exact committed-result receipt."""

        if (
            type(receipt) is not ApplicationChannelAdmissionReceipt
            or receipt._registry_token != id(self)
            or not _application_channel_admission_receipt_is_authentic(
                self._admission_secret,
                receipt,
            )
        ):
            return False
        if receipt._recoverable:
            with self._prepared_lock:
                return self._recoverable_admission_receipts.get(id(receipt)) is receipt or any(
                    retained.result.receipt is receipt
                    for retained in self._acknowledging_admission_results.values()
                )
        return True

    def authenticates_admission_receipt_proof(
        self,
        receipt: ApplicationChannelAdmissionReceipt,
    ) -> bool:
        """Authenticate an intact issued receipt after its recovery slot is acknowledged."""

        return bool(
            type(receipt) is ApplicationChannelAdmissionReceipt
            and receipt._registry_token == id(self)
            and _application_channel_admission_receipt_is_authentic(
                self._admission_secret,
                receipt,
            )
        )

    def authenticates_admission_result(self, result: object) -> bool:
        """Authenticate one exact outer result and its identity-bound common receipt."""

        if type(result) is not ApplicationChannelAdmissionResult:
            return False
        receipt = result.receipt
        return bool(
            type(receipt) is ApplicationChannelAdmissionReceipt
            and result.snapshot is receipt.snapshot
            and result.close_token is receipt.close_token
            and self.authenticates_admission_receipt(receipt)
        )

    def authenticates_admission_result_proof(self, result: object) -> bool:
        """Authenticate exact outer result bytes without requiring a live recovery slot."""

        if type(result) is not ApplicationChannelAdmissionResult:
            return False
        receipt = result.receipt
        return bool(
            type(receipt) is ApplicationChannelAdmissionReceipt
            and result.snapshot is receipt.snapshot
            and result.close_token is receipt.close_token
            and self.authenticates_admission_receipt_proof(receipt)
        )

    def _route_partition_id(self, namespace: str, semantic_id: str) -> int:
        canonical_digest = _canonical_route_digest(semantic_id)
        if canonical_digest is not None:
            # Partition on independent high bits: the packed map uses low bits
            # for open-addressed slots, so reusing them here would force every
            # key in one partition to share an initial probe position.
            return (canonical_digest >> 32) % self._shard_count
        return _stable_partition(namespace, semantic_id, self._shard_count)

    @staticmethod
    def _route_digest(route: PackedUniqueDigestMap, semantic_id: str) -> int:
        """Return a canonical packed ID digest or the map's namespaced fallback."""

        canonical_digest = _canonical_route_digest(semantic_id)
        return route.digest(semantic_id) if canonical_digest is None else canonical_digest

    def _route_locator(
        self,
        route: PackedUniqueDigestMap,
        semantic_id: str,
    ) -> int | None:
        """Resolve one collision-checked route token to its compact locator."""

        return route.get_digest(self._route_digest(route, semantic_id))

    def _owner_shard(
        self,
        shard_id: int,
        *,
        create: bool,
    ) -> _ApplicationChannelShard | None:
        shard = self._shards.get(shard_id)
        if shard is not None or not create:
            return shard
        with self._directory_lock:
            shard = self._shards.get(shard_id)
            if shard is None:
                shard = _ApplicationChannelShard(shard_id=shard_id)
                self._shards[shard_id] = shard
            return shard

    def _route_partition(
        self,
        namespace: str,
        semantic_id: str,
        *,
        create: bool,
    ) -> _RoutePartition | None:
        partition_id = self._route_partition_id(namespace, semantic_id)
        partition = self._route_partitions[partition_id]
        if partition is not None or not create:
            return partition
        with self._directory_lock:
            partition = self._route_partitions[partition_id]
            if partition is None:
                partition = _RoutePartition(partition_id=partition_id)
                self._route_partitions[partition_id] = partition
            return partition

    @staticmethod
    def _route_lock_entry(partition: _RoutePartition) -> tuple[tuple[int, int], RLock]:
        return (0, partition.partition_id), partition.lock

    @staticmethod
    def _owner_lock_entry(shard: _ApplicationChannelShard) -> tuple[tuple[int, int], RLock]:
        return (1, shard.shard_id), shard.lock

    def _require_window_time(
        self,
        value: datetime,
        field_name: str,
        *,
        allow_end_boundary: bool = False,
    ) -> datetime:
        canonical_time = value if value.tzinfo is UTC else ensure_utc(value)
        after_window = canonical_time > self._window_end or (
            canonical_time == self._window_end and not allow_end_boundary
        )
        if canonical_time < self._window_start or after_window:
            raise StateError(
                f"{field_name} {canonical_time.isoformat()} is outside the application "
                f"channel window [{self._window_start.isoformat()}, "
                f"{self._window_end.isoformat()})"
            )
        return canonical_time

    def _active_prepared_admission_locked(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> _ApplicationChannelAdmissionCapability:
        """Return the registry-owned capability for one intact active token."""

        capability = self._prepared_capabilities.get(id(token))
        if capability is None:
            if token._registry_token != id(self):
                raise StateError("application channel admission token belongs to another registry")
            raise StateError("application channel admission token is stale or already consumed")
        active = self._prepared_reservations.get(capability.reservation_id)
        if active is not token or capability.carrier_token is not token:
            raise StateError("application channel admission token is stale or already consumed")
        if not hmac.compare_digest(token._integrity_token, capability.integrity_token) or not (
            _application_channel_admission_token_is_authentic(
                self._admission_secret,
                token,
            )
        ):
            raise StateError("application channel admission token integrity validation failed")
        return capability

    def _has_incomplete_prepared_release_locked(self) -> bool:
        """Return whether an exact release/acknowledgement still owns the global fence."""

        return bool(
            self._releasing_reservations
            or self._acknowledging_admission_results
            or self._acknowledging_close_results
        )

    def _reject_prepared_conflict_locked(
        self,
        *,
        channel_ids: tuple[str, ...] = (),
        transport_ids: tuple[str, ...] = (),
        operation_ids: tuple[str, ...] = (),
        allowed_reservation_id: int | None = None,
        include_mutating: bool = True,
    ) -> None:
        """Reject a mutation that would cross one reserved semantic identity."""

        if self._has_incomplete_prepared_release_locked():
            raise StateError(
                "Application channel mutation is fenced by an incomplete prepared release"
            )

        for label, values, retained in (
            ("channel", channel_ids, self._prepared_channel_ids),
            ("transport", transport_ids, self._prepared_transport_ids),
            ("operation", operation_ids, self._prepared_operation_ids),
        ):
            for value in values:
                owner = retained.get(value)
                if owner is not None and owner != allowed_reservation_id:
                    raise StateError(
                        f"Application {label} identity {value!r} has a prepared admission"
                    )
        if not include_mutating:
            return
        for label, values, retained in (
            ("channel", channel_ids, self._mutating_channel_ids),
            ("transport", transport_ids, self._mutating_transport_ids),
            ("operation", operation_ids, self._mutating_operation_ids),
        ):
            for value in values:
                if retained.get(value, 0):
                    raise StateError(
                        f"Application {label} identity {value!r} has an in-flight mutation"
                    )

    @staticmethod
    def _increment_claims(retained: dict[str, int], values: tuple[str, ...]) -> None:
        """Increment exact transient mutation-claim counts."""

        for value in values:
            retained[value] = retained.get(value, 0) + 1

    @staticmethod
    def _decrement_claims(retained: dict[str, int], values: tuple[str, ...]) -> None:
        """Release exact transient mutation-claim counts."""

        for value in values:
            remaining = retained[value] - 1
            if remaining:
                retained[value] = remaining
            else:
                retained.pop(value)

    @contextmanager
    def _ordinary_mutation_admission(
        self,
        *,
        channel_ids: tuple[str, ...] = (),
        transport_ids: tuple[str, ...] = (),
        operation_ids: tuple[str, ...] = (),
        affinity_key: tuple[str, str] | None = None,
    ) -> Iterator[None]:
        """Claim exact keys briefly without serializing disjoint mutations."""

        normalized_channels = tuple(dict.fromkeys(value for value in channel_ids if value))
        normalized_transports = tuple(dict.fromkeys(value for value in transport_ids if value))
        normalized_operations = tuple(dict.fromkeys(value for value in operation_ids if value))
        with self._prepared_lock:
            self._reject_prepared_conflict_locked(
                channel_ids=normalized_channels,
                transport_ids=normalized_transports,
                operation_ids=normalized_operations,
                include_mutating=False,
            )
            self._increment_claims(self._mutating_channel_ids, normalized_channels)
            self._increment_claims(self._mutating_transport_ids, normalized_transports)
            self._increment_claims(self._mutating_operation_ids, normalized_operations)
            if affinity_key is not None:
                self._mutating_affinity_counts[affinity_key] = (
                    self._mutating_affinity_counts.get(affinity_key, 0) + 1
                )
        try:
            yield
        finally:
            with self._prepared_lock:
                self._decrement_claims(self._mutating_channel_ids, normalized_channels)
                self._decrement_claims(self._mutating_transport_ids, normalized_transports)
                self._decrement_claims(self._mutating_operation_ids, normalized_operations)
                if affinity_key is not None:
                    remaining = self._mutating_affinity_counts[affinity_key] - 1
                    if remaining:
                        self._mutating_affinity_counts[affinity_key] = remaining
                    else:
                        self._mutating_affinity_counts.pop(affinity_key)

    def _begin_ordinary_fresh_open_admission(
        self,
        identity: ApplicationChannelIdentity,
        reservation: ApplicationOperationReservation,
    ) -> None:
        """Claim one fresh channel/transport/operation tuple."""

        channel_id = identity.channel_id
        transport_id = identity.binding.transport_id
        operation_id = reservation.operation_id
        affinity_key = (identity.owner_id, identity.affinity_digest)
        with self._prepared_lock:
            self._reject_prepared_conflict_locked(
                channel_ids=(channel_id,),
                transport_ids=(transport_id,),
                operation_ids=(operation_id,),
                include_mutating=False,
            )
            self._mutating_channel_ids[channel_id] = (
                self._mutating_channel_ids.get(channel_id, 0) + 1
            )
            self._mutating_transport_ids[transport_id] = (
                self._mutating_transport_ids.get(transport_id, 0) + 1
            )
            self._mutating_operation_ids[operation_id] = (
                self._mutating_operation_ids.get(operation_id, 0) + 1
            )
            self._mutating_affinity_counts[affinity_key] = (
                self._mutating_affinity_counts.get(affinity_key, 0) + 1
            )

    def _end_ordinary_fresh_open_admission(
        self,
        identity: ApplicationChannelIdentity,
        reservation: ApplicationOperationReservation,
    ) -> None:
        """Release one tuple claimed by :meth:`_begin_ordinary_fresh_open_admission`."""

        channel_id = identity.channel_id
        transport_id = identity.binding.transport_id
        operation_id = reservation.operation_id
        affinity_key = (identity.owner_id, identity.affinity_digest)
        with self._prepared_lock:
            self._decrement_claims(self._mutating_channel_ids, (channel_id,))
            self._decrement_claims(self._mutating_transport_ids, (transport_id,))
            self._decrement_claims(self._mutating_operation_ids, (operation_id,))
            remaining = self._mutating_affinity_counts[affinity_key] - 1
            if remaining:
                self._mutating_affinity_counts[affinity_key] = remaining
            else:
                self._mutating_affinity_counts.pop(affinity_key)

    @contextmanager
    def _ordinary_fresh_open_admission(
        self,
        identity: ApplicationChannelIdentity,
        reservation: ApplicationOperationReservation,
    ) -> Iterator[None]:
        """Claim one fresh tuple for compatibility callers using a context manager."""

        self._begin_ordinary_fresh_open_admission(identity, reservation)
        try:
            yield
        finally:
            self._end_ordinary_fresh_open_admission(identity, reservation)

    def _register_prepared_admission_locked(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> None:
        """Publish only bounded reservation metadata, never channel state."""

        if self._has_incomplete_prepared_release_locked():
            raise StateError("Application channel preparation is fenced by an incomplete release")

        if not _application_channel_admission_token_is_authentic(
            self._admission_secret,
            token,
        ):
            raise StateError("application channel admission token integrity validation failed")
        reservation_id = token._reservation_id
        if token._retain_result_for_recovery:
            if len(self._recoverable_admission_slots) >= _MAX_RECOVERABLE_ADMISSION_RESULTS:
                raise StateError(
                    "Application admission recovery capacity is exhausted; acknowledge "
                    "a committed result before preparing another recoverable admission"
                )
        self._reject_prepared_conflict_locked(
            channel_ids=token._reserved_channel_ids,
            transport_ids=token._reserved_transport_ids,
            operation_ids=tuple(
                reservation.operation_id
                for reservation in (token.reservations or (token.reservation,))
            ),
        )
        affinity_key = (
            (token.identity.owner_id, token.identity.affinity_digest)
            if token.identity is not None and token.kind != "open_completed_batch_close"
            else None
        )
        capability = _ApplicationChannelAdmissionCapability(
            token_id=id(token),
            reservation_id=reservation_id,
            integrity_token=token._integrity_token,
            carrier_token=token,
            trusted_token=deepcopy(token),
            reserved_channel_ids=token._reserved_channel_ids,
            reserved_transport_ids=token._reserved_transport_ids,
            operation_ids=tuple(
                reservation.operation_id
                for reservation in (token.reservations or (token.reservation,))
            ),
            affinity_key=affinity_key,
            linearization_time=token.linearization_time,
            retain_result_for_recovery=token._retain_result_for_recovery,
        )
        self._prepared_reservations[reservation_id] = token
        self._prepared_capabilities[capability.token_id] = capability
        if capability.retain_result_for_recovery:
            self._recoverable_admission_slots.add(reservation_id)
        for channel_id in capability.reserved_channel_ids:
            self._prepared_channel_ids[channel_id] = reservation_id
        for transport_id in capability.reserved_transport_ids:
            self._prepared_transport_ids[transport_id] = reservation_id
        for operation_id in capability.operation_ids:
            self._prepared_operation_ids[operation_id] = reservation_id
        if affinity_key is not None:
            self._prepared_affinity_reservations.setdefault(affinity_key, set()).add(reservation_id)

    def _release_prepared_capability_locked(
        self,
        capability: _ApplicationChannelAdmissionCapability,
        *,
        keep_recovery_slot: bool = False,
        keep_release_marker: bool = False,
    ) -> None:
        """Release reservations using only the registry-owned immutable locator."""

        retained = self._prepared_capabilities.get(capability.token_id)
        if retained is not capability:
            return
        self._releasing_reservations.add(capability.reservation_id)
        if capability.retain_result_for_recovery and not keep_recovery_slot:
            self._recoverable_admission_slots.discard(capability.reservation_id)
        self._claimed_reservations.discard(capability.reservation_id)
        for channel_id in capability.reserved_channel_ids:
            if self._prepared_channel_ids.get(channel_id) == capability.reservation_id:
                self._prepared_channel_ids.pop(channel_id)
        for transport_id in capability.reserved_transport_ids:
            if self._prepared_transport_ids.get(transport_id) == capability.reservation_id:
                self._prepared_transport_ids.pop(transport_id)
        for operation_id in capability.operation_ids:
            if self._prepared_operation_ids.get(operation_id) == capability.reservation_id:
                self._prepared_operation_ids.pop(operation_id)
        self._release_prepared_affinity_reservation_locked(capability)
        self._prepared_release_fault("admission-secondary-indexes")
        journal = self._prepared_commit_journals.get(capability.reservation_id)
        if journal is not None:
            shard = self._owner_shard(
                capability.trusted_token._owner_shard_id,
                create=False,
            )
            if shard is not None:
                with shard.lock:
                    self._release_prepared_accounting_marker(
                        shard,
                        capability.reservation_id,
                    )
        self._prepared_release_fault("admission-accounting-marker")
        self._prepared_commit_journals.pop(capability.reservation_id, None)
        self._prepared_reservations.pop(capability.reservation_id, None)
        self._prepared_release_fault("admission-primary-token")
        if keep_release_marker:
            self._prepared_capabilities.pop(capability.token_id, None)
            self._prepared_release_fault("admission-capability")
        else:
            self._releasing_reservations.discard(capability.reservation_id)
            self._prepared_capabilities.pop(capability.token_id, None)
        if not self._prepared_reservations and not self._prepared_close_tokens:
            # CPython dictionaries retain peak-sized tables after individual
            # pops.  Emptying them explicitly keeps prepare/cancel churn from
            # becoming duration-retained state and restores exact census size.
            self._prepared_reservations.clear()
            self._prepared_capabilities.clear()
            self._claimed_reservations.clear()
            self._prepared_channel_ids.clear()
            self._prepared_transport_ids.clear()
            self._prepared_operation_ids.clear()
            self._prepared_affinity_reservations.clear()

    def _release_prepared_affinity_reservation_locked(
        self,
        capability: _ApplicationChannelAdmissionCapability,
    ) -> None:
        """Release exact affinity capacity idempotently for one preparation."""

        affinity_key = capability.affinity_key
        if affinity_key is None:
            return
        reservations = self._prepared_affinity_reservations.get(affinity_key)
        if reservations is None:
            return
        reservations.discard(capability.reservation_id)
        if not reservations:
            self._prepared_affinity_reservations.pop(affinity_key, None)

    @staticmethod
    def _effective_deadline(snapshot: ApplicationChannelSnapshot) -> datetime:
        return min(
            snapshot.idle_deadline,
            snapshot.identity.hard_deadline,
            snapshot.identity.binding.closes_at,
        )

    @staticmethod
    def _is_reusable_at(snapshot: ApplicationChannelSnapshot, at: datetime) -> bool:
        return (
            snapshot.is_open
            and snapshot.identity.opened_at <= at
            and at < ApplicationChannelRegistry._effective_deadline(snapshot)
        )

    def _pack_channel_locator(self, shard_id: int, handle: int) -> int:
        """Pack one owner-shard/handle pair into a route-map integer."""

        return handle * self._shard_count + shard_id

    def _unpack_channel_locator(self, locator: int) -> tuple[int, int]:
        """Return ``(shard_id, handle)`` from one packed route-map integer."""

        handle, shard_id = divmod(locator, self._shard_count)
        return shard_id, handle

    @staticmethod
    def _set_active_deadline(
        shard: _ApplicationChannelShard,
        handle: int,
        snapshot: ApplicationChannelSnapshot,
    ) -> None:
        deadline = ApplicationChannelRegistry._effective_deadline(snapshot).timestamp()
        shard.active_expiry.set(handle, deadline)

    @staticmethod
    def _ensure_expiry_value(
        index: PackedHandleExpiryIndex,
        handle: int,
        expected: float | None,
    ) -> None:
        """Converge one exact expiry owner without duplicating heap records."""

        current = index.get(handle)
        if expected is None:
            if current is not None:
                index.pop(handle, None)
            return
        if current != expected:
            index.set(handle, expected)

    def _ensure_route_value(
        self,
        route: PackedUniqueDigestMap,
        semantic_id: str,
        locator: int,
    ) -> None:
        """Install one deterministic packed route or validate its exact replay."""

        digest = self._route_digest(route, semantic_id)
        current = route.get_digest(digest)
        if current is None:
            route.set_digest(digest, locator)
        elif current != locator:
            raise StateError(
                f"Application route for {semantic_id!r} changed during prepared commit"
            )

    def _prepared_commit_fault(self, stage: str) -> None:
        """Fault-injection seam between retryable prepared-commit primitives."""

        del stage

    def _prepared_retention_fault(self, stage: str) -> None:
        """Fault-injection seam around exact terminal-result retention."""

        del stage

    def _prepared_release_fault(self, stage: str) -> None:
        """Fault-injection seam inside idempotent prepared-owner release."""

        del stage

    def _apply_prepared_accounting(
        self,
        shard: _ApplicationChannelShard,
        journal: _ApplicationChannelCommitJournal | _ApplicationChannelCloseCommitJournal,
        *,
        estimated_delta: int,
        mutation_delta: int,
        open_delta: int = 0,
        minimum_affinity_bucket: int | None = None,
        minimum_high_water_mark: int | None = None,
        stage: str,
    ) -> None:
        """Apply all prepared counters through one atomic accounting-object swap."""

        accounting = shard._accounting
        if journal.reservation_id in accounting.prepared_commit_ids:
            journal.accounting_applied = True
            return
        open_channels = accounting.open_channels + open_delta
        if open_channels < 0:
            raise StateError("Application open-channel count would underflow")
        updated = replace(
            accounting,
            estimated_value_bytes=accounting.estimated_value_bytes + estimated_delta,
            mutation_version=accounting.mutation_version + mutation_delta,
            open_channels=open_channels,
            maximum_affinity_bucket=(
                accounting.maximum_affinity_bucket
                if minimum_affinity_bucket is None
                else max(accounting.maximum_affinity_bucket, minimum_affinity_bucket)
            ),
            high_water_mark=(
                accounting.high_water_mark
                if minimum_high_water_mark is None
                else max(accounting.high_water_mark, minimum_high_water_mark)
            ),
            prepared_commit_ids=accounting.prepared_commit_ids | {journal.reservation_id},
        )
        shard._accounting = updated
        # The durable marker lives inside the same immutable object as every
        # counter. A fault here therefore replays as an exact no-op.
        self._prepared_commit_fault(f"{stage}-installed")
        journal.accounting_applied = True

    @staticmethod
    def _release_prepared_accounting_marker(
        shard: _ApplicationChannelShard,
        reservation_id: int,
    ) -> None:
        """Remove one acknowledged accounting marker without changing counters."""

        accounting = shard._accounting
        if reservation_id not in accounting.prepared_commit_ids:
            return
        shard._accounting = replace(
            accounting,
            prepared_commit_ids=accounting.prepared_commit_ids - {reservation_id},
        )

    def _channel_route(self, channel_id: str) -> tuple[_RoutePartition, int, int] | None:
        partition = self._route_partition("channel", channel_id, create=False)
        if partition is None:
            return None
        with partition.lock:
            locator = self._route_locator(partition.channels, channel_id)
        if locator is None:
            return None
        shard_id, handle = self._unpack_channel_locator(locator)
        return partition, shard_id, handle

    def _operation_route(self, operation_id: str) -> tuple[_RoutePartition, int, int] | None:
        partition = self._route_partition("operation", operation_id, create=False)
        if partition is None:
            return None
        with partition.lock:
            locator = partition.operations.get(operation_id)
        if locator is None:
            return None
        shard_id, handle = self._unpack_channel_locator(locator)
        return partition, shard_id, handle

    def prepare_open_channel_with_completed_operation(
        self,
        identity: ApplicationChannelIdentity,
        reservation: ApplicationOperationReservation,
        *,
        replacement_channel_id: str = "",
        replacement_closed_at: datetime | None = None,
        replacement_reason: str = "",
        retain_result_for_recovery: bool = False,
    ) -> ApplicationChannelAdmissionToken:
        """Reserve a fresh channel and first completed operation without publishing them."""

        return self._prepare_open_channel_with_completed_operation(
            identity,
            reservation,
            replacement_channel_id=replacement_channel_id,
            replacement_closed_at=replacement_closed_at,
            replacement_reason=replacement_reason,
            retain_result_for_recovery=retain_result_for_recovery,
        )

    def prepare_open_channel_with_completed_operations_and_close(
        self,
        identity: ApplicationChannelIdentity,
        reservations: tuple[ApplicationOperationReservation, ...],
        *,
        closed_at: datetime,
        reason: str,
    ) -> ApplicationChannelAdmissionToken:
        """Reserve a fresh channel, bounded completed batch, and atomic close."""

        if type(reservations) is not tuple or not reservations or len(reservations) > 64:
            raise ValueError("Completed application-operation batches require 1..64 members")
        if any(type(item) is not ApplicationOperationReservation for item in reservations):
            raise TypeError("Completed application-operation batch members must be exact models")
        if (
            identity.budget.operations != len(reservations)
            or identity.budget.initiator_bytes != sum(item.initiator_bytes for item in reservations)
            or identity.budget.responder_bytes != sum(item.responder_bytes for item in reservations)
        ):
            raise StateError(
                "Completed application-operation batch must exactly consume its budget"
            )
        return self._prepare_open_channel_with_completed_operation(
            identity,
            reservations[0],
            additional_reservations=reservations[1:],
            channel_closed_at=closed_at,
            channel_close_reason=reason,
            retain_result_for_recovery=True,
            force_terminal_batch=True,
        )

    def prepare_open_channel_with_completed_operation_and_close(
        self,
        identity: ApplicationChannelIdentity,
        reservation: ApplicationOperationReservation,
        *,
        closed_at: datetime,
        reason: str,
        replacement_channel_id: str = "",
        replacement_closed_at: datetime | None = None,
        replacement_reason: str = "",
        retain_result_for_recovery: bool = False,
    ) -> ApplicationChannelAdmissionToken:
        """Reserve one fresh channel, completed operation, and exact atomic close."""

        return self._prepare_open_channel_with_completed_operation(
            identity,
            reservation,
            channel_closed_at=closed_at,
            channel_close_reason=reason,
            replacement_channel_id=replacement_channel_id,
            replacement_closed_at=replacement_closed_at,
            replacement_reason=replacement_reason,
            retain_result_for_recovery=retain_result_for_recovery,
        )

    def _prepare_open_channel_with_completed_operation(
        self,
        identity: ApplicationChannelIdentity,
        reservation: ApplicationOperationReservation,
        *,
        channel_closed_at: datetime | None = None,
        channel_close_reason: str = "",
        replacement_channel_id: str = "",
        replacement_closed_at: datetime | None = None,
        replacement_reason: str = "",
        retain_result_for_recovery: bool = False,
        additional_reservations: tuple[ApplicationOperationReservation, ...] = (),
        force_terminal_batch: bool = False,
    ) -> ApplicationChannelAdmissionToken:
        """Reserve a fresh channel and first completed operation without publishing them.

        An optional exact replacement is validated and reserved as part of the
        same token.  This lets HTTP retain the prior reusable transport when an
        external transport transaction aborts, while a successful commit closes
        the prior channel immediately before opening its replacement.
        """

        reservations = (reservation, *additional_reservations)
        terminal_batch = bool(force_terminal_batch and channel_closed_at is not None)
        if len({item.operation_id for item in reservations}) != len(reservations):
            raise StateError("Completed application-operation batch repeats an operation ID")
        if additional_reservations and replacement_channel_id:
            raise StateError("Completed application-operation batches cannot replace a channel")
        for ordinal, item in enumerate(reservations):
            if item.channel_id != identity.channel_id:
                raise StateError(
                    "Completed application operations must target the channel being opened"
                )
            if item.parent_operation_id:
                raise StateError("Initial completed application operations cannot have parents")
            if item.ordinal != ordinal:
                raise StateError(
                    "Completed application-operation batch ordinals must be contiguous from zero"
                )
        replacement_id = replacement_channel_id.strip()
        if bool(replacement_id) != (replacement_closed_at is not None):
            raise ValueError(
                "replacement_channel_id and replacement_closed_at must be supplied together"
            )
        reason = replacement_reason.strip()
        if replacement_id and not reason:
            raise ValueError("A prepared application-channel replacement requires a reason")
        close_reason = channel_close_reason.strip()
        if (channel_closed_at is None) != (not close_reason):
            raise ValueError("channel closed_at and close reason must be supplied together")
        if retain_result_for_recovery and (
            replacement_id
            or (
                channel_closed_at is not None and not additional_reservations and not terminal_batch
            )
        ):
            raise StateError(
                "Recoverable application opens cannot replace or singly close a channel; use "
                "the prepared close-only admission or a terminal completed batch"
            )
        prepared_identity = _PackedChannelStore.prepare_identity(identity)

        with self._gate.mutation(), self._prepared_lock:
            opened_at = self._require_window_time(identity.opened_at, "channel opened_at")
            if opened_at < self._watermark:
                raise StateError("Application channels cannot open before the current watermark")
            if identity.hard_deadline > self._window_end:
                raise StateError("Application channel hard_deadline must be inside the window")
            self._reject_prepared_conflict_locked(
                channel_ids=tuple(
                    candidate for candidate in (identity.channel_id, replacement_id) if candidate
                ),
                transport_ids=(identity.binding.transport_id,),
                operation_ids=tuple(item.operation_id for item in reservations),
            )
            if self.get(identity.channel_id) is not None:
                raise StateError(f"Duplicate application channel_id {identity.channel_id!r}")
            transport_route = self._route_partition(
                "transport",
                identity.binding.transport_id,
                create=False,
            )
            if transport_route is not None:
                with transport_route.lock:
                    retained_transport = self._route_locator(
                        transport_route.transports,
                        identity.binding.transport_id,
                    )
                if retained_transport is not None:
                    raise StateError(
                        f"Transport {identity.binding.transport_id!r} already owns open channel "
                        "or retained channel"
                    )
            for item in reservations:
                operation_route = self._route_partition(
                    "operation",
                    item.operation_id,
                    create=False,
                )
                if operation_route is not None:
                    with operation_route.lock:
                        if item.operation_id in operation_route.operations:
                            raise StateError(f"Duplicate active operation_id {item.operation_id!r}")

            owner_shard_id = self._owner_shard_id(identity.owner_id)
            shard = self._owner_shard(owner_shard_id, create=False)
            affinity_size = 0
            replacement_snapshot: ApplicationChannelSnapshot | None = None
            replacement_handle: int | None = None
            replacement_generation: int | None = None
            if shard is not None and not terminal_batch:
                with shard.lock:
                    affinity_size = shard.channels.count_prepared_affinity(prepared_identity)
            if replacement_id:
                routed = self._channel_route(replacement_id)
                if routed is None:
                    raise StateError(f"Unknown replacement application channel {replacement_id!r}")
                _replacement_route, replacement_shard_id, replacement_handle = routed
                if replacement_shard_id != owner_shard_id:
                    raise StateError("Replacement application channel belongs to another owner")
                replacement_shard = self._owner_shard(replacement_shard_id, create=False)
                if replacement_shard is None:
                    raise StateError(f"Unknown replacement application channel {replacement_id!r}")
                with replacement_shard.lock:
                    replacement_snapshot = replacement_shard.channels.get_by_handle(
                        replacement_handle
                    )
                    replacement_generation = replacement_shard.channels.generation(
                        replacement_handle
                    )
                    if not replacement_snapshot.is_open:
                        raise StateError("Replacement application channel is already closed")
                    if (
                        replacement_snapshot.identity.owner_id != identity.owner_id
                        or replacement_snapshot.identity.affinity_digest != identity.affinity_digest
                    ):
                        raise StateError(
                            "Replacement application channel must share owner and affinity"
                        )
                    canonical_close = self._require_window_time(
                        replacement_closed_at,
                        "replacement closed_at",
                        allow_end_boundary=True,
                    )
                    if canonical_close < self._watermark:
                        raise StateError(
                            "Application channels cannot close before the current watermark"
                        )
                    if canonical_close < replacement_snapshot.identity.opened_at:
                        raise StateError("Application channel cannot close before it opens")
                    if canonical_close < replacement_snapshot.last_activity_at:
                        raise StateError(
                            "Application channel cannot close before its last activity"
                        )
                    if canonical_close > self._effective_deadline(replacement_snapshot):
                        raise StateError(
                            "Application channel cannot close after its idle, hard, or "
                            "transport deadline"
                        )
                    if replacement_shard.operations.count("channel", replacement_id):
                        raise StateError(
                            f"Application channel {replacement_id!r} cannot be replaced with "
                            "active operations"
                        )
                affinity_size -= 1

            if not terminal_batch:
                affinity_key = (identity.owner_id, identity.affinity_digest)
                affinity_size += len(self._prepared_affinity_reservations.get(affinity_key, ()))
                affinity_size += self._mutating_affinity_counts.get(affinity_key, 0)
                if affinity_size >= self._max_reusable_per_affinity:
                    raise StateError(
                        f"Application affinity {identity.affinity_digest!r} already retains "
                        f"{affinity_size} reusable channels; limit is "
                        f"{self._max_reusable_per_affinity}"
                    )
            completed = self._initial_completed_snapshot(identity, reservations[0])
            for item in reservations[1:]:
                completed = self._updated_for_operation(
                    completed,
                    item,
                    completes_immediately=True,
                )
            canonical_channel_close: datetime | None = None
            if channel_closed_at is not None:
                canonical_channel_close = self._require_window_time(
                    channel_closed_at,
                    "channel closed_at",
                    allow_end_boundary=True,
                )
                if canonical_channel_close < self._watermark:
                    raise StateError(
                        "Application channels cannot close before the current watermark"
                    )
                if canonical_channel_close < completed.last_activity_at:
                    raise StateError(
                        "Prepared application channel close cannot precede its operation"
                    )
                if canonical_channel_close > self._effective_deadline(completed):
                    raise StateError(
                        "Application channel cannot close after its idle, hard, or "
                        "transport deadline"
                    )
                completed = replace(
                    completed,
                    closed_at=canonical_channel_close,
                    close_reason=close_reason,
                )
            reservation_id = self._next_prepared_reservation_id
            self._next_prepared_reservation_id += 1
            token = ApplicationChannelAdmissionToken(
                kind=(
                    "open_completed_batch_close"
                    if terminal_batch
                    else "open_completed_close"
                    if canonical_channel_close is not None
                    else "open_completed"
                ),
                reservation=reservation,
                reservations=reservations,
                identity=identity,
                replacement_channel_id=replacement_id,
                replacement_closed_at=(
                    ensure_utc(replacement_closed_at) if replacement_closed_at is not None else None
                ),
                replacement_reason=reason,
                channel_closed_at=canonical_channel_close,
                channel_close_reason=close_reason,
                _registry_token=id(self),
                _reservation_id=reservation_id,
                _owner_shard_id=owner_shard_id,
                _channel_handle=replacement_handle,
                _channel_generation=replacement_generation,
                _expected_snapshot=replacement_snapshot,
                _prepared_snapshot=completed,
                _reserved_channel_ids=tuple(
                    candidate for candidate in (identity.channel_id, replacement_id) if candidate
                ),
                _reserved_transport_ids=(identity.binding.transport_id,),
                _retain_result_for_recovery=retain_result_for_recovery,
            )
            token = replace(
                token,
                _integrity_token=_application_channel_admission_integrity_token(
                    self._admission_secret,
                    token,
                ),
            )
            self._register_prepared_admission_locked(token)
            return token

    def prepare_completed_operation(
        self,
        reservation: ApplicationOperationReservation,
        *,
        retain_result_for_recovery: bool = False,
    ) -> ApplicationChannelAdmissionToken:
        """Reserve one immediate operation without consuming channel budget."""

        return self._prepare_completed_operation(
            reservation,
            retain_result_for_recovery=retain_result_for_recovery,
        )

    def prepare_completed_operation_and_close(
        self,
        reservation: ApplicationOperationReservation,
        *,
        closed_at: datetime,
        reason: str,
        retain_result_for_recovery: bool = False,
    ) -> ApplicationChannelAdmissionToken:
        """Reserve one immediate operation and its exact atomic channel close."""

        return self._prepare_completed_operation(
            reservation,
            closed_at=closed_at,
            close_reason=reason,
            retain_result_for_recovery=retain_result_for_recovery,
        )

    def _prepare_completed_operation(
        self,
        reservation: ApplicationOperationReservation,
        *,
        closed_at: datetime | None = None,
        close_reason: str = "",
        retain_result_for_recovery: bool = False,
    ) -> ApplicationChannelAdmissionToken:
        """Build one sealed immediate-operation token with an optional close."""

        reason = close_reason.strip()
        if (closed_at is None) != (not reason):
            raise ValueError("closed_at and close reason must be supplied together")
        if retain_result_for_recovery and closed_at is not None:
            raise StateError(
                "Recoverable completed operations cannot close the channel; use the "
                "prepared close-only admission"
            )

        with self._gate.mutation(), self._prepared_lock:
            canonical_close: datetime | None = None
            if closed_at is not None:
                canonical_close = self._require_window_time(
                    closed_at,
                    "channel closed_at",
                    allow_end_boundary=True,
                )
                if canonical_close < self._watermark:
                    raise StateError(
                        "Application channels cannot close before the current watermark"
                    )
            self._reject_prepared_conflict_locked(
                channel_ids=(reservation.channel_id,),
                operation_ids=(reservation.operation_id,),
            )
            routed = self._channel_route(reservation.channel_id)
            if routed is None:
                raise StateError(
                    f"Unknown application channel {reservation.channel_id!r} for operation "
                    f"{reservation.operation_id!r}"
                )
            _channel_route, shard_id, channel_handle = routed
            shard = self._owner_shard(shard_id, create=False)
            if shard is None:
                raise StateError(f"Unknown application channel {reservation.channel_id!r}")
            operation_route = self._route_partition(
                "operation",
                reservation.operation_id,
                create=False,
            )
            lock_entries = [self._owner_lock_entry(shard)]
            if operation_route is not None:
                lock_entries.append(self._route_lock_entry(operation_route))
            with _acquire_stable_locks(lock_entries):
                snapshot = shard.channels.get_by_handle(channel_handle)
                generation = shard.channels.generation(channel_handle)
                if snapshot.channel_id != reservation.channel_id:
                    raise StateError(f"Unknown application channel {reservation.channel_id!r}")
                if operation_route is not None:
                    if reservation.operation_id in operation_route.operations:
                        raise StateError(
                            f"Duplicate active operation_id {reservation.operation_id!r}"
                        )
                used_id_key = (channel_handle, reservation.operation_id)
                if used_id_key in shard.used_operation_ids:
                    raise StateError(
                        f"Operation_id {reservation.operation_id!r} was already used by channel "
                        f"{reservation.channel_id!r}"
                    )
                if reservation.parent_operation_id:
                    parent = shard.operations.get(reservation.parent_operation_id)
                    if parent is None:
                        raise StateError(
                            f"Operation {reservation.operation_id!r} references inactive parent "
                            f"{reservation.parent_operation_id!r}"
                        )
                    if parent.channel_id != reservation.channel_id:
                        raise StateError(
                            "Application child operation must share its parent's channel"
                        )
                    if (
                        reservation.started_at < parent.started_at
                        or reservation.ended_at > parent.ended_at
                    ):
                        raise StateError(
                            f"Operation {reservation.operation_id!r} is not contained by parent "
                            f"{parent.operation_id!r}"
                        )
                updated = self._updated_for_operation(
                    snapshot,
                    reservation,
                    completes_immediately=True,
                )
                if canonical_close is not None:
                    if canonical_close < updated.last_activity_at:
                        raise StateError(
                            "Prepared application channel close cannot precede its operation"
                        )
                    if canonical_close > self._effective_deadline(updated):
                        raise StateError(
                            "Application channel cannot close after its idle, hard, or "
                            "transport deadline"
                        )
                    active_count = shard.operations.count("channel", reservation.channel_id)
                    if active_count:
                        raise StateError(
                            f"Application channel {reservation.channel_id!r} cannot close with "
                            f"{active_count} active operations"
                        )
                    updated = replace(
                        updated,
                        closed_at=canonical_close,
                        close_reason=reason,
                    )
            reservation_id = self._next_prepared_reservation_id
            self._next_prepared_reservation_id += 1
            token = ApplicationChannelAdmissionToken(
                kind=(
                    "completed_operation_close"
                    if canonical_close is not None
                    else "completed_operation"
                ),
                reservation=reservation,
                channel_closed_at=canonical_close,
                channel_close_reason=reason,
                _registry_token=id(self),
                _reservation_id=reservation_id,
                _owner_shard_id=shard_id,
                _channel_handle=channel_handle,
                _channel_generation=generation,
                _expected_snapshot=snapshot,
                _prepared_snapshot=updated,
                _reserved_channel_ids=(reservation.channel_id,),
                _retain_result_for_recovery=retain_result_for_recovery,
            )
            token = replace(
                token,
                _integrity_token=_application_channel_admission_integrity_token(
                    self._admission_secret,
                    token,
                ),
            )
            self._register_prepared_admission_locked(token)
            return token

    def _active_prepared_close_locked(
        self,
        token: ApplicationChannelPreparedCloseToken,
    ) -> _ApplicationChannelPreparedCloseCapability:
        """Return one exact intact close capability retained by this registry."""

        if type(token) is not ApplicationChannelPreparedCloseToken:
            raise StateError("application channel prepared close token is copied or stale")
        try:
            canonical = _application_channel_prepared_close_token_payload(token)
            integrity_token = _prepared_close_proof_digest(
                token._integrity_token,
                "token.integrity",
            )
        except (OverflowError, ValueError) as error:
            raise StateError(
                "application channel prepared close token integrity validation failed"
            ) from error
        if token._registry_token != id(self):
            raise StateError("application channel prepared close token is foreign")
        expected = hmac.new(self._admission_secret, canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(integrity_token, expected):
            raise StateError("application channel prepared close token integrity validation failed")
        capability = self._prepared_close_capabilities.get(id(token))
        if capability is None or capability.token_id != id(token):
            raise StateError("application channel prepared close token is copied or stale")
        active = self._prepared_close_tokens.get(capability.reservation_id)
        if active is not token:
            raise StateError("application channel prepared close token is copied or stale")
        if not hmac.compare_digest(integrity_token, capability.integrity_token):
            raise StateError("application channel prepared close token integrity validation failed")
        return capability

    def _release_prepared_close_locked(
        self,
        capability: _ApplicationChannelPreparedCloseCapability,
        *,
        keep_recovery_slot: bool = False,
        keep_release_marker: bool = False,
    ) -> None:
        """Release one close claim using only its trusted registry locator."""

        retained = self._prepared_close_capabilities.get(capability.token_id)
        if retained is not capability:
            return
        self._releasing_reservations.add(capability.reservation_id)
        token = capability.trusted_token
        self._claimed_reservations.discard(capability.reservation_id)
        if self._prepared_channel_ids.get(token.channel_id) == capability.reservation_id:
            self._prepared_channel_ids.pop(token.channel_id)
        if not keep_recovery_slot:
            self._recoverable_admission_slots.discard(capability.reservation_id)
            if not self._recoverable_admission_slots:
                self._recoverable_admission_slots.clear()
        self._prepared_release_fault("close-secondary-indexes")
        journal = self._prepared_close_commit_journals.get(capability.reservation_id)
        if journal is not None:
            shard = self._owner_shard(
                capability.trusted_token._owner_shard_id,
                create=False,
            )
            if shard is not None:
                with shard.lock:
                    self._release_prepared_accounting_marker(
                        shard,
                        capability.reservation_id,
                    )
        self._prepared_release_fault("close-accounting-marker")
        self._prepared_close_commit_journals.pop(capability.reservation_id, None)
        self._prepared_close_tokens.pop(capability.reservation_id, None)
        self._prepared_release_fault("close-primary-token")
        if keep_release_marker:
            self._prepared_close_capabilities.pop(capability.token_id, None)
            self._prepared_release_fault("close-capability")
        else:
            self._releasing_reservations.discard(capability.reservation_id)
            self._prepared_close_capabilities.pop(capability.token_id, None)
        if not self._prepared_close_tokens:
            self._prepared_close_tokens.clear()
            self._prepared_close_capabilities.clear()
        if not self._prepared_reservations and not self._prepared_close_tokens:
            self._claimed_reservations.clear()
            self._prepared_channel_ids.clear()
            self._prepared_transport_ids.clear()
            self._prepared_operation_ids.clear()
            self._prepared_affinity_reservations.clear()

    def prepare_close_channel(
        self,
        channel_id: str,
        *,
        closed_at: datetime,
        reason: str,
    ) -> ApplicationChannelPreparedCloseToken:
        """Reserve one close-only mutation without publishing canonical state."""

        canonical_channel = channel_id.strip()
        canonical_reason = reason.strip()
        if not canonical_channel:
            raise ValueError("Application prepared close requires a channel_id")
        if not canonical_reason:
            raise ValueError("Application prepared close requires a reason")
        with self._gate.mutation(), self._prepared_lock:
            canonical_close = self._require_window_time(
                closed_at,
                "channel closed_at",
                allow_end_boundary=True,
            )
            if canonical_close < self._watermark:
                raise StateError("Application channels cannot close before the current watermark")
            if len(self._recoverable_admission_slots) >= _MAX_RECOVERABLE_ADMISSION_RESULTS:
                raise StateError(
                    "Application admission recovery capacity is exhausted; acknowledge "
                    "a committed result before preparing another recoverable admission"
                )
            self._reject_prepared_conflict_locked(channel_ids=(canonical_channel,))
            routed = self._channel_route(canonical_channel)
            if routed is None:
                raise StateError(f"Unknown application channel {canonical_channel!r}")
            _channel_route, shard_id, channel_handle = routed
            shard = self._owner_shard(shard_id, create=False)
            if shard is None:
                raise StateError(f"Unknown application channel {canonical_channel!r}")
            with shard.lock:
                snapshot = shard.channels.detached_by_handle(channel_handle)
                generation = shard.channels.generation(channel_handle)
                if snapshot.channel_id != canonical_channel:
                    raise StateError(f"Unknown application channel {canonical_channel!r}")
                if not snapshot.is_open:
                    raise StateError("Application prepared close requires an open channel")
                if canonical_close < snapshot.last_activity_at:
                    raise StateError("Application channel cannot close before its last activity")
                if canonical_close > self._effective_deadline(snapshot):
                    raise StateError(
                        "Application channel cannot close after its idle, hard, or "
                        "transport deadline"
                    )
                active_count = shard.operations.count("channel", canonical_channel)
                if active_count:
                    raise StateError(
                        f"Application channel {canonical_channel!r} cannot close with "
                        f"{active_count} active operations"
                    )
                prepared_snapshot = replace(
                    snapshot,
                    closed_at=canonical_close,
                    close_reason=canonical_reason,
                )
            reservation_id = self._next_prepared_reservation_id
            self._next_prepared_reservation_id += 1
            token = ApplicationChannelPreparedCloseToken(
                channel_id=canonical_channel,
                closed_at=canonical_close,
                reason=canonical_reason,
                _registry_token=id(self),
                _reservation_id=reservation_id,
                _owner_shard_id=shard_id,
                _channel_handle=channel_handle,
                _channel_generation=generation,
                _expected_snapshot=snapshot,
                _prepared_snapshot=prepared_snapshot,
            )
            token = replace(
                token,
                _integrity_token=_application_channel_prepared_close_integrity_token(
                    self._admission_secret,
                    token,
                ),
            )
            expected_projection = _detached_application_channel_snapshot(snapshot)
            terminal_projection = _detached_application_channel_snapshot(prepared_snapshot)
            identity = expected_projection.identity
            projection = ApplicationChannelPreparedCloseProjection(
                publication_token=token.publication_token,
                channel_id=identity.channel_id,
                owner_id=identity.owner_id,
                protocol=identity.protocol,
                affinity_digest=identity.affinity_digest,
                transport_id=identity.binding.transport_id,
                owner_partition_id=shard_id,
                channel_handle=channel_handle,
                channel_generation=generation,
                expected_current=expected_projection,
                projected_terminal=terminal_projection,
                cumulative_initiator_bytes=expected_projection.reserved_initiator_bytes,
                cumulative_responder_bytes=expected_projection.reserved_responder_bytes,
                cumulative_operations=expected_projection.reserved_operations,
                completed_operations=expected_projection.completed_operations,
                active_operations=expected_projection.active_operations,
                closed_at=canonical_close,
                close_reason=canonical_reason,
                _registry_token=id(self),
                _reservation_id=reservation_id,
                _prepared_token_id=id(token),
            )
            projection = replace(
                projection,
                _integrity_token=(
                    _application_channel_prepared_close_projection_integrity_token(
                        self._admission_secret,
                        projection,
                    )
                ),
            )
            if not _prepared_close_projection_matches_token(token, projection):
                raise StateError("Application prepared close projection is internally inconsistent")
            projection_authority = _ApplicationChannelPreparedCloseProjectionAuthority(
                token_id=id(token),
                reservation_id=reservation_id,
                integrity_token=projection.proof_token,
                public_projection=projection,
                trusted_projection=_detached_prepared_close_projection(projection),
            )
            capability = _ApplicationChannelPreparedCloseCapability(
                token_id=id(token),
                reservation_id=reservation_id,
                integrity_token=token._integrity_token,
                trusted_token=deepcopy(token),
                projection_authority=projection_authority,
            )
            self._prepared_close_tokens[reservation_id] = token
            self._prepared_close_capabilities[id(token)] = capability
            self._prepared_channel_ids[canonical_channel] = reservation_id
            self._recoverable_admission_slots.add(reservation_id)
            return token

    def _prepared_close_projection_authority_locked(
        self,
        token: ApplicationChannelPreparedCloseToken,
    ) -> _ApplicationChannelPreparedCloseProjectionAuthority | None:
        """Locate proof authority from active or committed charged retention."""

        if not _application_channel_prepared_close_token_is_authentic(
            self._admission_secret,
            token,
        ):
            return None
        reservation_id = token._reservation_id
        if type(reservation_id) is not int:
            return None
        retained = self._recoverable_close_results.get(reservation_id)
        if retained is None:
            retained = self._acknowledging_close_results.get(reservation_id)
        if retained is not None and retained.token is token:
            authority = retained.projection_authority
            if authority.token_id == id(token) and authority.reservation_id == reservation_id:
                return authority
        capability = self._prepared_close_capabilities.get(id(token))
        if capability is not None:
            try:
                active = self._active_prepared_close_locked(token)
            except StateError:
                return None
            return active.projection_authority
        return None

    def _authenticates_prepared_close_projection_locked(
        self,
        token: ApplicationChannelPreparedCloseToken,
        projection: ApplicationChannelPreparedCloseProjection,
    ) -> bool:
        """Validate exact retained proof membership without consulting live channel rows."""

        authority = self._prepared_close_projection_authority_locked(token)
        if authority is None or authority.public_projection is not projection:
            return False
        if not _application_channel_prepared_close_projection_is_authentic(
            self._admission_secret,
            projection,
        ) or not _application_channel_prepared_close_projection_is_authentic(
            self._admission_secret,
            authority.trusted_projection,
        ):
            return False
        if (
            authority.token_id != id(token)
            or authority.reservation_id != token._reservation_id
            or projection._prepared_token_id != authority.token_id
            or projection._reservation_id != authority.reservation_id
        ):
            return False
        try:
            public_integrity = _prepared_close_proof_digest(
                projection._integrity_token,
                "projection.integrity",
            )
            trusted_integrity = _prepared_close_proof_digest(
                authority.trusted_projection._integrity_token,
                "trusted projection.integrity",
            )
            authority_integrity = _prepared_close_proof_digest(
                authority.integrity_token,
                "projection authority.integrity",
            )
        except ValueError:
            return False
        return (
            hmac.compare_digest(public_integrity, authority_integrity)
            and hmac.compare_digest(trusted_integrity, authority_integrity)
            and _prepared_close_projection_matches_token(token, projection)
            and _prepared_close_projection_matches_token(
                token,
                authority.trusted_projection,
            )
        )

    def prepared_close_projection(
        self,
        token: ApplicationChannelPreparedCloseToken,
    ) -> ApplicationChannelPreparedCloseProjection:
        """Return the exact detached proof retained for one close capability."""

        if not _application_channel_prepared_close_token_is_authentic(
            self._admission_secret,
            token,
        ):
            raise StateError("application channel prepared close token is copied or stale")
        with self._prepared_lock:
            authority = self._prepared_close_projection_authority_locked(token)
            if authority is None:
                raise StateError("application channel prepared close token is copied or stale")
            projection = authority.public_projection
            if not self._authenticates_prepared_close_projection_locked(token, projection):
                raise StateError(
                    "application channel prepared close projection integrity validation failed"
                )
            return projection

    def authenticates_prepared_close_projection(
        self,
        token: ApplicationChannelPreparedCloseToken,
        projection: ApplicationChannelPreparedCloseProjection,
    ) -> bool:
        """Return whether an exact owner/token/projection capability remains retained."""

        if type(projection) is not ApplicationChannelPreparedCloseProjection:
            return False
        if not _application_channel_prepared_close_token_is_authentic(
            self._admission_secret,
            token,
        ):
            return False
        with self._prepared_lock:
            return self._authenticates_prepared_close_projection_locked(token, projection)

    def cancel_prepared_close(self, token: ApplicationChannelPreparedCloseToken) -> bool:
        """Cancel one unclaimed close-only reservation without mutation."""

        with self._gate.mutation(), self._prepared_lock:
            capability = self._prepared_close_capabilities.get(id(token))
            if capability is None:
                return False
            try:
                capability = self._active_prepared_close_locked(token)
            except StateError:
                self._release_prepared_close_locked(capability)
                raise
            if capability.reservation_id in self._claimed_reservations:
                return False
            self._release_prepared_close_locked(capability)
            return True

    def _validate_prepared_close_locked(
        self,
        capability: _ApplicationChannelPreparedCloseCapability,
    ) -> None:
        """Verify exact handle/generation/snapshot state before a close claim commits."""

        token = capability.trusted_token
        shard = self._owner_shard(token._owner_shard_id, create=False)
        if shard is None:
            raise StateError("prepared application close channel disappeared")
        with shard.lock:
            if not shard.channels.matches(
                token._channel_handle,
                token._channel_generation,
                token.channel_id,
            ):
                raise StateError("prepared application close channel was invalidated")
            if shard.channels.detached_by_handle(token._channel_handle) != token._expected_snapshot:
                raise StateError("prepared application close channel changed")

    def _claim_prepared_close(self, token: ApplicationChannelPreparedCloseToken) -> None:
        """Revalidate and claim one close reservation in a short common section."""

        with self._gate.mutation(), self._prepared_lock:
            if self._has_incomplete_prepared_release_locked():
                raise StateError(
                    "Application close claim is fenced by an incomplete prepared release"
                )
            capability = self._prepared_close_capabilities.get(id(token))
            try:
                capability = self._active_prepared_close_locked(token)
            except StateError:
                if capability is not None:
                    self._release_prepared_close_locked(capability)
                raise
            if capability.reservation_id in self._claimed_reservations:
                raise StateError("application channel prepared close is already claimed")
            if capability.trusted_token.closed_at < self._watermark:
                self._release_prepared_close_locked(capability)
                raise StateError("application prepared close starts behind the canonical watermark")
            try:
                self._validate_prepared_close_locked(capability)
                self._active_prepared_close_locked(token)
            except StateError:
                self._release_prepared_close_locked(capability)
                raise
            self._claimed_reservations.add(capability.reservation_id)

    def _cancel_claimed_close(self, token: ApplicationChannelPreparedCloseToken) -> None:
        """Release one claimed close after its outer transaction aborts."""

        with self._gate.mutation(), self._prepared_lock:
            capability = self._prepared_close_capabilities.get(id(token))
            if capability is None:
                return
            try:
                capability = self._active_prepared_close_locked(token)
            except StateError:
                self._release_prepared_close_locked(capability)
                return
            if capability.reservation_id not in self._claimed_reservations:
                raise StateError("application channel prepared close is not claimed")
            self._release_prepared_close_locked(capability)

    @contextmanager
    def prepared_close(
        self,
        token: ApplicationChannelPreparedCloseToken,
    ) -> Iterator[ApplicationChannelPreparedCloseCommit]:
        """Claim one close-only admission without retaining locks externally."""

        self._claim_prepared_close(token)
        transaction = ApplicationChannelPreparedCloseCommit(self, token)
        try:
            yield transaction
        finally:
            if not transaction.committed and transaction.recovery_status != "indeterminate":
                self._cancel_claimed_close(token)
            transaction._close()

    def _commit_prepared_close_locked(
        self,
        token: ApplicationChannelPreparedCloseToken,
    ) -> ApplicationChannelCloseAdmissionResult:
        """Converge the exact close mutation after any primitive lost return."""

        journal = self._prepared_close_commit_journals.get(token._reservation_id)
        if journal is None:
            journal = _ApplicationChannelCloseCommitJournal(token._reservation_id)
            self._prepared_close_commit_journals[token._reservation_id] = journal
        channel_route = self._route_partition("channel", token.channel_id, create=False)
        shard = self._owner_shard(token._owner_shard_id, create=False)
        if channel_route is None or shard is None:
            raise StateError("prepared application close channel disappeared")
        with _acquire_stable_locks(
            [self._route_lock_entry(channel_route), self._owner_lock_entry(shard)]
        ):
            locator = self._pack_channel_locator(
                token._owner_shard_id,
                token._channel_handle,
            )
            if self._route_locator(channel_route.channels, token.channel_id) != locator:
                raise StateError("prepared application close route changed")
            if not shard.channels.matches(
                token._channel_handle,
                token._channel_generation,
                token.channel_id,
            ):
                raise StateError("prepared application close generation changed")
            expected = token._expected_snapshot
            updated = token._prepared_snapshot
            assert expected is not None and updated is not None
            snapshot = shard.channels.detached_by_handle(token._channel_handle)
            if snapshot == expected:
                if shard.operations.count("channel", token.channel_id):
                    raise StateError(
                        f"Application channel {token.channel_id!r} cannot close with "
                        "active operations"
                    )
                shard.channels.replace(
                    token._channel_handle,
                    updated,
                    known_prior=expected,
                )
            elif snapshot != updated:
                raise StateError("prepared application close snapshot is indeterminate")
            self._prepared_commit_fault("close-row")

            closed_deadline = (token.closed_at + self._closed_grace).timestamp()
            self._ensure_expiry_value(shard.active_expiry, token._channel_handle, None)
            self._ensure_expiry_value(
                shard.operation_blocker_expiry,
                token._channel_handle,
                None,
            )
            self._ensure_expiry_value(
                shard.closed_expiry,
                token._channel_handle,
                closed_deadline,
            )
            self._prepared_commit_fault("close-expiry")

            self._apply_prepared_accounting(
                shard,
                journal,
                estimated_delta=(
                    _snapshot_estimated_bytes(updated) - _snapshot_estimated_bytes(expected)
                ),
                mutation_delta=1,
                open_delta=-1,
                stage="close-accounting",
            )
            self._prepared_commit_fault("close-accounting")

            if (
                shard.channels.detached_by_handle(token._channel_handle) != updated
                or shard.active_expiry.get(token._channel_handle) is not None
                or shard.operation_blocker_expiry.get(token._channel_handle) is not None
                or shard.closed_expiry.get(token._channel_handle) != closed_deadline
            ):
                raise StateError("Prepared application close poststate is incomplete")
        close = ApplicationChannelCloseResult(
            channel_id=token.channel_id,
            closed_at=token.closed_at,
            newly_closed=True,
            retirement_proof=self._retirement_proof_for_snapshot(updated),
        )
        placeholder = ApplicationChannelCloseAdmissionReceipt(
            publication_token=token.publication_token,
            channel_id=token.channel_id,
            snapshot=updated,
            close=close,
            _registry_token=id(self),
        )
        receipt = replace(
            placeholder,
            _integrity_token=_application_channel_close_receipt_integrity_token(
                self._admission_secret,
                placeholder,
            ),
        )
        return ApplicationChannelCloseAdmissionResult(updated, close, receipt)

    def _retain_recoverable_close_locked(
        self,
        capability: _ApplicationChannelPreparedCloseCapability,
        result: ApplicationChannelCloseAdmissionResult,
    ) -> None:
        """Retain one exact close result in its preparation-reserved slot."""

        if capability.reservation_id not in self._recoverable_admission_slots:
            raise StateError("Application close lost its reserved recovery capacity")
        token = self._prepared_close_tokens.get(capability.reservation_id)
        if token is None or id(token) != capability.token_id:
            raise StateError("Application close lost its exact recovery token")
        self._recoverable_close_receipts[id(result.receipt)] = result.receipt
        try:
            self._prepared_retention_fault("close-receipt")
            self._recoverable_close_results[capability.reservation_id] = (
                _RecoverableApplicationCloseResult(
                    token,
                    result,
                    capability.projection_authority,
                )
            )
        except BaseException:
            if capability.reservation_id not in self._recoverable_close_results:
                self._recoverable_close_receipts.pop(id(result.receipt), None)
            raise
        self._prepared_retention_fault("close-result")

    def _commit_claimed_close(
        self,
        token: ApplicationChannelPreparedCloseToken,
    ) -> ApplicationChannelCloseAdmissionResult:
        """Commit and retain one exact claimed close result."""

        with self._gate.mutation(), self._prepared_lock:
            capability = self._active_prepared_close_locked(token)
            if capability.reservation_id not in self._claimed_reservations:
                raise StateError("application channel prepared close is not claimed")
            self._validate_prepared_close_locked(capability)
            self._active_prepared_close_locked(token)
            result = self._commit_prepared_close_locked(capability.trusted_token)
            self._retain_recoverable_close_locked(capability, result)
            return result

    def _reconcile_claimed_close(
        self,
        token: ApplicationChannelPreparedCloseToken,
    ) -> ApplicationChannelCloseCommitRecovery:
        """Return exact committed, certified-prestate, or indeterminate close truth."""

        if not _application_channel_prepared_close_token_is_authentic(
            self._admission_secret,
            token,
        ):
            return ApplicationChannelCloseCommitRecovery("indeterminate")
        with self._gate.mutation(), self._prepared_lock:
            retained = self._recoverable_close_results.get(token._reservation_id)
            if retained is None:
                retained = self._acknowledging_close_results.get(token._reservation_id)
            if retained is not None:
                if retained.token is token:
                    if (
                        self._recoverable_close_receipts.get(id(retained.result.receipt))
                        is not retained.result.receipt
                        and self._acknowledging_close_results.get(token._reservation_id)
                        is not retained
                    ):
                        return ApplicationChannelCloseCommitRecovery("indeterminate")
                    return ApplicationChannelCloseCommitRecovery(
                        "committed",
                        retained.result,
                    )
                return ApplicationChannelCloseCommitRecovery("indeterminate")
            capability = self._prepared_close_capabilities.get(id(token))
            if capability is None:
                return ApplicationChannelCloseCommitRecovery("indeterminate")
            try:
                capability = self._active_prepared_close_locked(token)
            except StateError:
                return ApplicationChannelCloseCommitRecovery("indeterminate")
            if capability.reservation_id not in self._claimed_reservations:
                return ApplicationChannelCloseCommitRecovery("indeterminate")
            trusted = capability.trusted_token
            if capability.reservation_id in self._prepared_close_commit_journals:
                result = self._commit_prepared_close_locked(trusted)
                self._retain_recoverable_close_locked(capability, result)
                return ApplicationChannelCloseCommitRecovery("committed", result)
            channel_route = self._route_partition(
                "channel",
                trusted.channel_id,
                create=False,
            )
            shard = self._owner_shard(trusted._owner_shard_id, create=False)
            if shard is None or channel_route is None:
                return ApplicationChannelCloseCommitRecovery("indeterminate")
            with _acquire_stable_locks(
                [self._route_lock_entry(channel_route), self._owner_lock_entry(shard)]
            ):
                locator = self._pack_channel_locator(
                    trusted._owner_shard_id,
                    trusted._channel_handle,
                )
                if self._route_locator(channel_route.channels, trusted.channel_id) != locator:
                    return ApplicationChannelCloseCommitRecovery("indeterminate")
                if not shard.channels.matches(
                    trusted._channel_handle,
                    trusted._channel_generation,
                    trusted.channel_id,
                ):
                    return ApplicationChannelCloseCommitRecovery("indeterminate")
                snapshot = shard.channels.detached_by_handle(trusted._channel_handle)
                if snapshot == trusted._expected_snapshot:
                    return ApplicationChannelCloseCommitRecovery("not_committed")
                return ApplicationChannelCloseCommitRecovery("indeterminate")

    def recover_committed_close(
        self,
        token: ApplicationChannelPreparedCloseToken,
    ) -> ApplicationChannelCloseAdmissionResult | None:
        """Return one exact retained close result after a lost outer return."""

        if not _application_channel_prepared_close_token_is_authentic(
            self._admission_secret,
            token,
        ):
            return None
        with self._prepared_lock:
            retained = self._recoverable_close_results.get(token._reservation_id)
            if retained is None:
                retained = self._acknowledging_close_results.get(token._reservation_id)
            if retained is None or retained.token is not token:
                return None
            return retained.result

    def reconcile_committed_close(
        self,
        token: ApplicationChannelPreparedCloseToken,
    ) -> ApplicationChannelCloseCommitRecovery:
        """Reconcile one exact retained indeterminate close after context exit."""

        if not _application_channel_prepared_close_token_is_authentic(
            self._admission_secret,
            token,
        ):
            return ApplicationChannelCloseCommitRecovery("indeterminate")
        recovery = self._reconcile_claimed_close(token)
        if recovery.status == "not_committed":
            with self._gate.mutation(), self._prepared_lock:
                capability = self._prepared_close_capabilities.get(id(token))
                if capability is not None:
                    capability = self._active_prepared_close_locked(token)
                    self._claimed_reservations.discard(capability.reservation_id)
        return recovery

    def acknowledge_committed_close(
        self,
        token: ApplicationChannelPreparedCloseToken,
        result: ApplicationChannelCloseAdmissionResult,
    ) -> bool:
        """Consume one exact close recovery result after outer commit."""

        if not _application_channel_prepared_close_token_is_authentic(
            self._admission_secret,
            token,
        ):
            return False
        with self._gate.mutation(), self._prepared_lock:
            acknowledging = self._acknowledging_close_results.get(token._reservation_id)
            retained = self._recoverable_close_results.get(token._reservation_id)
            if retained is None:
                retained = acknowledging
            if retained is None or retained.token is not token or retained.result is not result:
                return False
            self._acknowledging_close_results[token._reservation_id] = retained
            self._prepared_retention_fault("close-ack-record")
            capability = self._prepared_close_capabilities.get(id(token))
            if capability is not None:
                self._release_prepared_close_locked(
                    capability,
                    keep_recovery_slot=True,
                    keep_release_marker=True,
                )
            elif (
                token._reservation_id not in self._releasing_reservations and acknowledging is None
            ):
                return False
            self._recoverable_admission_slots.discard(token._reservation_id)
            self._prepared_release_fault("close-ack-slot")
            self._recoverable_close_results.pop(token._reservation_id, None)
            self._prepared_release_fault("close-ack-result")
            self._recoverable_close_receipts.pop(id(result.receipt), None)
            self._prepared_release_fault("close-ack-receipt")
            if not self._recoverable_close_results:
                self._recoverable_close_results.clear()
                self._recoverable_close_receipts.clear()
            if not self._recoverable_admission_slots:
                self._recoverable_admission_slots.clear()
            self._releasing_reservations.discard(token._reservation_id)
            self._prepared_release_fault("close-ack-release-marker")
            self._acknowledging_close_results.pop(token._reservation_id, None)
            if not self._acknowledging_close_results:
                self._acknowledging_close_results.clear()
            return True

    def authenticates_close_admission_receipt(
        self,
        receipt: ApplicationChannelCloseAdmissionReceipt,
    ) -> bool:
        """Return whether one exact unacknowledged close receipt is authentic."""

        if type(
            receipt
        ) is not ApplicationChannelCloseAdmissionReceipt or receipt._registry_token != id(self):
            return False
        expected = _application_channel_close_receipt_integrity_token(
            self._admission_secret,
            receipt,
        )
        if not hmac.compare_digest(receipt._integrity_token, expected):
            return False
        with self._prepared_lock:
            return self._recoverable_close_receipts.get(id(receipt)) is receipt or any(
                retained.result.receipt is receipt
                for retained in self._acknowledging_close_results.values()
            )

    def cancel_prepared_admission(self, token: ApplicationChannelAdmissionToken) -> bool:
        """Cancel one unclaimed channel reservation without publishing state."""

        with self._gate.mutation(), self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                if (
                    type(token) is ApplicationChannelAdmissionToken
                    and token._registry_token == id(self)
                    and token._reservation_id in self._releasing_reservations
                    and _application_channel_admission_token_is_authentic(
                        self._admission_secret,
                        token,
                    )
                ):
                    self._releasing_reservations.discard(token._reservation_id)
                    return True
                return False
            try:
                capability = self._active_prepared_admission_locked(token)
            except StateError:
                self._release_prepared_capability_locked(capability)
                raise
            if capability.reservation_id in self._claimed_reservations:
                return False
            self._release_prepared_capability_locked(capability)
            return True

    @contextmanager
    def prepared_admission(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> Iterator[ApplicationChannelPreparedCommit]:
        """Claim a coupled admission without retaining channel locks externally."""

        self._claim_prepared_admission(token)
        transaction = ApplicationChannelPreparedCommit(self, token)
        try:
            yield transaction
        finally:
            if not transaction.committed and transaction.recovery_status != "indeterminate":
                self._cancel_claimed_admission(token)
            transaction._close()

    def _claim_prepared_admission(self, token: ApplicationChannelAdmissionToken) -> None:
        """Revalidate and claim one token in a short registry-only section."""

        with self._gate.mutation(), self._prepared_lock:
            if self._has_incomplete_prepared_release_locked():
                raise StateError(
                    "Application admission claim is fenced by an incomplete prepared release"
                )
            capability = self._prepared_capabilities.get(id(token))
            try:
                capability = self._active_prepared_admission_locked(token)
            except StateError:
                if capability is not None:
                    self._release_prepared_capability_locked(capability)
                raise
            if capability.reservation_id in self._claimed_reservations:
                raise StateError("application channel admission token is already claimed")
            if capability.linearization_time < self._watermark:
                self._release_prepared_capability_locked(capability)
                raise StateError(
                    "application channel admission starts behind the canonical watermark"
                )
            try:
                self._validate_prepared_admission_state_locked(capability.trusted_token)
                self._active_prepared_admission_locked(token)
            except StateError:
                self._release_prepared_capability_locked(capability)
                raise
            self._claimed_reservations.add(capability.reservation_id)

    def _validate_prepared_admission_state_locked(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> None:
        """Verify that visible state still matches one reserved token."""

        if token.kind in {
            "open_completed",
            "open_completed_batch_close",
            "open_completed_close",
        }:
            assert token.identity is not None
            if self.get(token.identity.channel_id) is not None:
                raise StateError("prepared application channel identity became occupied")
            transport_route = self._route_partition(
                "transport",
                token.identity.binding.transport_id,
                create=False,
            )
            if transport_route is not None:
                with transport_route.lock:
                    if (
                        self._route_locator(
                            transport_route.transports,
                            token.identity.binding.transport_id,
                        )
                        is not None
                    ):
                        raise StateError("prepared application transport identity became occupied")
            if token.replacement_channel_id:
                assert token._channel_handle is not None
                shard = self._owner_shard(token._owner_shard_id, create=False)
                if shard is None:
                    raise StateError("prepared replacement application channel disappeared")
                with shard.lock:
                    if not shard.channels.matches(
                        token._channel_handle,
                        token._channel_generation or 0,
                        token.replacement_channel_id,
                    ):
                        raise StateError("prepared replacement application channel was invalidated")
                    if (
                        shard.channels.get_by_handle(token._channel_handle)
                        != token._expected_snapshot
                    ):
                        raise StateError("prepared replacement application channel changed")
            return

        assert token._channel_handle is not None
        shard = self._owner_shard(token._owner_shard_id, create=False)
        if shard is None:
            raise StateError("prepared application operation channel disappeared")
        with shard.lock:
            if not shard.channels.matches(
                token._channel_handle,
                token._channel_generation or 0,
                token.reservation.channel_id,
            ):
                raise StateError("prepared application operation channel was invalidated")
            if shard.channels.get_by_handle(token._channel_handle) != token._expected_snapshot:
                raise StateError("prepared application operation channel changed")

    def _cancel_claimed_admission(self, token: ApplicationChannelAdmissionToken) -> None:
        """Release one claim after its external transaction aborts."""

        with self._gate.mutation(), self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                return
            try:
                self._active_prepared_admission_locked(token)
            except StateError:
                self._release_prepared_capability_locked(capability)
                return
            if capability.reservation_id not in self._claimed_reservations:
                raise StateError("application channel admission token is not claimed")
            self._release_prepared_capability_locked(capability)

    def _issue_admission_result_locked(
        self,
        capability: _ApplicationChannelAdmissionCapability,
        result: ApplicationChannelAdmissionResult,
    ) -> ApplicationChannelAdmissionResult:
        """Seal one committed common result against its exact trusted reservation."""

        trusted_token = capability.trusted_token
        receipt = ApplicationChannelAdmissionReceipt(
            kind=trusted_token.kind,
            publication_token=capability.integrity_token,
            channel_id=result.snapshot.channel_id,
            operation_id=trusted_token.reservation.operation_id,
            operation_ids=tuple(
                reservation.operation_id
                for reservation in (trusted_token.reservations or (trusted_token.reservation,))
            ),
            snapshot=result.snapshot,
            close_token=result.close_token,
            _registry_token=id(self),
            _recoverable=capability.retain_result_for_recovery,
        )
        receipt = replace(
            receipt,
            _integrity_token=_application_channel_admission_receipt_integrity_token(
                self._admission_secret,
                receipt,
            ),
        )
        return replace(result, receipt=receipt)

    def _retain_recoverable_admission_result_locked(
        self,
        capability: _ApplicationChannelAdmissionCapability,
        result: ApplicationChannelAdmissionResult,
    ) -> None:
        """Retain one exact result in the capacity reserved by its preparation."""

        if not capability.retain_result_for_recovery:
            return
        if capability.reservation_id not in self._recoverable_admission_slots:
            raise StateError("Application admission lost its reserved recovery capacity")
        receipt = result.receipt
        if receipt is None or not receipt._recoverable:
            raise StateError("Recoverable application admission returned no exact receipt")
        active_token = self._prepared_reservations.get(capability.reservation_id)
        if active_token is None or id(active_token) != capability.token_id:
            raise StateError("Recoverable application admission lost its exact token")
        retained = _RecoverableApplicationAdmissionResult(
            token=active_token,
            result=result,
        )
        self._recoverable_admission_receipts[id(receipt)] = receipt
        try:
            self._prepared_retention_fault("admission-receipt")
            self._recoverable_admission_results[capability.reservation_id] = retained
        except BaseException:
            if capability.reservation_id not in self._recoverable_admission_results:
                self._recoverable_admission_receipts.pop(id(receipt), None)
            raise
        self._prepared_retention_fault("admission-result")

    def _recover_committed_result_from_state_locked(
        self,
        capability: _ApplicationChannelAdmissionCapability,
    ) -> ApplicationChannelAdmissionResult | None:
        """Certify a fully committed result after the common return became ambiguous."""

        token = capability.trusted_token
        expected = token._prepared_snapshot
        if expected is None:
            return None
        channel_id = expected.channel_id
        routed = self._channel_route(channel_id)
        if routed is None:
            return None
        _channel_route, shard_id, channel_handle = routed
        if shard_id != token._owner_shard_id:
            return None
        shard = self._owner_shard(shard_id, create=False)
        if shard is None:
            return None
        with shard.lock:
            try:
                snapshot = shard.channels.get_by_handle(channel_handle)
            except KeyError:
                return None
            if snapshot != expected:
                return None
            reservations = token.reservations or (token.reservation,)
            if any(
                (channel_handle, reservation.operation_id) not in shard.used_operation_ids
                for reservation in reservations
            ):
                return None
            if token.kind in {"completed_operation", "completed_operation_close"} and (
                token._channel_handle != channel_handle
                or not shard.channels.matches(
                    channel_handle,
                    token._channel_generation or 0,
                    channel_id,
                )
            ):
                return None
            close_token = (
                ApplicationChannelCloseToken(
                    locator=self._pack_channel_locator(shard_id, channel_handle),
                    generation=shard.channels.generation(channel_handle),
                )
                if token.kind == "open_completed"
                else None
            )
        if token.identity is not None:
            transport_route = self._route_partition(
                "transport",
                token.identity.binding.transport_id,
                create=False,
            )
            if transport_route is None:
                return None
            with transport_route.lock:
                if self._route_locator(
                    transport_route.transports,
                    token.identity.binding.transport_id,
                ) != self._pack_channel_locator(shard_id, channel_handle):
                    return None
        if token.replacement_channel_id:
            replacement = self.get(token.replacement_channel_id)
            if (
                replacement is None
                or replacement.closed_at != token.replacement_closed_at
                or replacement.close_reason != token.replacement_reason
            ):
                return None
        return ApplicationChannelAdmissionResult(snapshot=snapshot, close_token=close_token)

    def _prepared_admission_prestate_is_intact_locked(
        self,
        capability: _ApplicationChannelAdmissionCapability,
    ) -> bool:
        """Return whether every canonical owner still equals the trusted prestate."""

        token = capability.trusted_token
        if token.kind in {
            "open_completed",
            "open_completed_batch_close",
            "open_completed_close",
        }:
            assert token.identity is not None
            shard = self._owner_shard(token._owner_shard_id, create=False)
            if shard is not None:
                with shard.lock:
                    if (
                        shard.channels.recovery_handle_for_channel(
                            token.identity.owner_id,
                            token.identity.channel_id,
                        )
                        is not None
                    ):
                        return False
            channel_route = self._route_partition(
                "channel",
                token.identity.channel_id,
                create=False,
            )
            if channel_route is not None:
                with channel_route.lock:
                    if (
                        self._route_locator(
                            channel_route.channels,
                            token.identity.channel_id,
                        )
                        is not None
                    ):
                        return False
            transport_route = self._route_partition(
                "transport",
                token.identity.binding.transport_id,
                create=False,
            )
            if transport_route is not None:
                with transport_route.lock:
                    if (
                        self._route_locator(
                            transport_route.transports,
                            token.identity.binding.transport_id,
                        )
                        is not None
                    ):
                        return False
            if token.replacement_channel_id:
                replacement = self.get(token.replacement_channel_id)
                return replacement == token._expected_snapshot
            return True

        shard = self._owner_shard(token._owner_shard_id, create=False)
        if shard is None or token._channel_handle is None:
            return False
        with shard.lock:
            if not shard.channels.matches(
                token._channel_handle,
                token._channel_generation or 0,
                token.reservation.channel_id,
            ):
                return False
            if shard.channels.detached_by_handle(token._channel_handle) != token._expected_snapshot:
                return False
            return (
                token._channel_handle,
                token.reservation.operation_id,
            ) not in shard.used_operation_ids

    def _reconcile_claimed_admission(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> ApplicationChannelCommitRecovery:
        """Return exact committed, certified-prestate, or indeterminate truth."""

        if type(token) is not ApplicationChannelAdmissionToken:
            return ApplicationChannelCommitRecovery("indeterminate")
        with self._gate.mutation(), self._prepared_lock:
            retained_result = self._recoverable_admission_results.get(token._reservation_id)
            if retained_result is None:
                retained_result = self._acknowledging_admission_results.get(token._reservation_id)
            if retained_result is not None:
                if retained_result.token is token:
                    receipt = retained_result.result.receipt
                    if receipt is None or (
                        self._recoverable_admission_receipts.get(id(receipt)) is not receipt
                        and self._acknowledging_admission_results.get(token._reservation_id)
                        is not retained_result
                    ):
                        return ApplicationChannelCommitRecovery("indeterminate")
                    return ApplicationChannelCommitRecovery(
                        "committed",
                        retained_result.result,
                    )
                return ApplicationChannelCommitRecovery("indeterminate")
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                return ApplicationChannelCommitRecovery("indeterminate")
            if (
                capability.trusted_token.kind == "open_completed_batch_close"
                and not capability.retain_result_for_recovery
            ):
                trusted_token = capability.trusted_token
                if capability.reservation_id in self._prepared_commit_journals:
                    result = self._commit_prepared_open_locked(trusted_token)
                else:
                    result = self._recover_committed_result_from_state_locked(capability)
                    if result is None:
                        if self._prepared_admission_prestate_is_intact_locked(capability):
                            self._release_prepared_capability_locked(capability)
                            return ApplicationChannelCommitRecovery("not_committed")
                        return ApplicationChannelCommitRecovery("indeterminate")
                result = self._issue_admission_result_locked(capability, result)
                self._release_prepared_capability_locked(capability)
                return ApplicationChannelCommitRecovery("committed", result)
            if not capability.retain_result_for_recovery:
                if self._prepared_admission_prestate_is_intact_locked(capability):
                    self._release_prepared_capability_locked(capability)
                    return ApplicationChannelCommitRecovery("not_committed")
                return ApplicationChannelCommitRecovery("indeterminate")
            try:
                capability = self._active_prepared_admission_locked(token)
            except StateError:
                if self._prepared_admission_prestate_is_intact_locked(capability):
                    self._release_prepared_capability_locked(capability)
                    return ApplicationChannelCommitRecovery("not_committed")
                return ApplicationChannelCommitRecovery("indeterminate")
            if capability.reservation_id not in self._claimed_reservations:
                return ApplicationChannelCommitRecovery("indeterminate")
            if capability.reservation_id in self._prepared_commit_journals:
                trusted_token = capability.trusted_token
                if trusted_token.kind in {
                    "open_completed",
                    "open_completed_batch_close",
                    "open_completed_close",
                }:
                    result = self._commit_prepared_open_locked(trusted_token)
                else:
                    result = self._commit_prepared_operation_locked(trusted_token)
                result = self._issue_admission_result_locked(capability, result)
                self._retain_recoverable_admission_result_locked(capability, result)
                self._release_prepared_affinity_reservation_locked(capability)
                return ApplicationChannelCommitRecovery("committed", result)
            result = self._recover_committed_result_from_state_locked(capability)
            if result is not None:
                result = self._issue_admission_result_locked(capability, result)
                self._retain_recoverable_admission_result_locked(capability, result)
                self._release_prepared_affinity_reservation_locked(capability)
                return ApplicationChannelCommitRecovery("committed", result)
            if self._prepared_admission_prestate_is_intact_locked(capability):
                return ApplicationChannelCommitRecovery("not_committed")
            return ApplicationChannelCommitRecovery("indeterminate")

    def recover_committed_admission(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> ApplicationChannelAdmissionResult | None:
        """Return one exact retained common result after a lost outer return."""

        if not _application_channel_admission_token_is_authentic(
            self._admission_secret,
            token,
        ):
            return None
        with self._prepared_lock:
            retained = self._recoverable_admission_results.get(token._reservation_id)
            if retained is None:
                retained = self._acknowledging_admission_results.get(token._reservation_id)
            if retained is None or retained.token is not token:
                return None
            result = retained.result
        return result if self.authenticates_admission_result(result) else None

    def reconcile_committed_admission(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> ApplicationChannelCommitRecovery:
        """Reconcile one exact retained indeterminate claim after context exit."""

        if not _application_channel_admission_token_is_authentic(
            self._admission_secret,
            token,
        ):
            return ApplicationChannelCommitRecovery("indeterminate")
        recovery = self._reconcile_claimed_admission(token)
        if recovery.status == "not_committed":
            with self._gate.mutation(), self._prepared_lock:
                capability = self._prepared_capabilities.get(id(token))
                if capability is not None:
                    capability = self._active_prepared_admission_locked(token)
                    self._claimed_reservations.discard(capability.reservation_id)
        return recovery

    def acknowledge_committed_admission(
        self,
        token: ApplicationChannelAdmissionToken,
        result: ApplicationChannelAdmissionResult,
    ) -> bool:
        """Consume the exact retained recovery result after its outer owner commits."""

        if not _application_channel_admission_token_is_authentic(
            self._admission_secret,
            token,
        ) or not self.authenticates_admission_result(result):
            return False
        with self._gate.mutation(), self._prepared_lock:
            acknowledging = self._acknowledging_admission_results.get(token._reservation_id)
            retained = self._recoverable_admission_results.get(token._reservation_id)
            if retained is None:
                retained = acknowledging
            if retained is None or retained.token is not token or retained.result is not result:
                return False
            self._acknowledging_admission_results[token._reservation_id] = retained
            self._prepared_retention_fault("admission-ack-record")
            capability = self._prepared_capabilities.get(id(token))
            if capability is not None:
                self._release_prepared_capability_locked(
                    capability,
                    keep_recovery_slot=True,
                    keep_release_marker=True,
                )
            elif (
                token._reservation_id not in self._releasing_reservations and acknowledging is None
            ):
                return False
            receipt = result.receipt
            self._recoverable_admission_slots.discard(token._reservation_id)
            self._prepared_release_fault("admission-ack-slot")
            self._recoverable_admission_results.pop(token._reservation_id, None)
            self._prepared_release_fault("admission-ack-result")
            if receipt is not None:
                self._recoverable_admission_receipts.pop(id(receipt), None)
            self._prepared_release_fault("admission-ack-receipt")
            if not self._recoverable_admission_results:
                self._recoverable_admission_results.clear()
                self._recoverable_admission_receipts.clear()
            if not self._recoverable_admission_slots:
                self._recoverable_admission_slots.clear()
            self._releasing_reservations.discard(token._reservation_id)
            self._prepared_release_fault("admission-ack-release-marker")
            self._acknowledging_admission_results.pop(token._reservation_id, None)
            if not self._acknowledging_admission_results:
                self._acknowledging_admission_results.clear()
            return True

    def _commit_claimed_admission(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> ApplicationChannelAdmissionResult:
        """Commit one claimed admission in a short final channel critical section."""

        with self._gate.mutation(), self._prepared_lock:
            capability = self._active_prepared_admission_locked(token)
            if capability.reservation_id not in self._claimed_reservations:
                raise StateError("application channel admission token is not claimed")
            trusted_token = capability.trusted_token
            self._validate_prepared_admission_state_locked(trusted_token)
            self._active_prepared_admission_locked(token)
            if trusted_token.kind in {
                "open_completed",
                "open_completed_batch_close",
                "open_completed_close",
            }:
                result = self._commit_prepared_open_locked(trusted_token)
            else:
                result = self._commit_prepared_operation_locked(trusted_token)
            result = self._issue_admission_result_locked(capability, result)
            self._retain_recoverable_admission_result_locked(capability, result)
            if capability.retain_result_for_recovery:
                self._release_prepared_affinity_reservation_locked(capability)
            else:
                self._release_prepared_capability_locked(capability)
            return result

    def _commit_prepared_open_locked(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> ApplicationChannelAdmissionResult:
        """Perform primitive replacement/open writes after claim validation."""

        if token._retain_result_for_recovery or token.kind == "open_completed_batch_close":
            return self._commit_recoverable_open_locked(token)

        identity = token.identity
        completed = token._prepared_snapshot
        assert identity is not None and completed is not None
        prepared_identity = _PackedChannelStore.prepare_identity(identity)
        shard = self._owner_shard(token._owner_shard_id, create=True)
        channel_route = self._route_partition("channel", identity.channel_id, create=True)
        transport_route = self._route_partition(
            "transport",
            identity.binding.transport_id,
            create=True,
        )
        reservations = token.reservations or (token.reservation,)
        terminal_batch = token.kind == "open_completed_batch_close"
        operation_routes = (
            ()
            if terminal_batch
            else tuple(
                self._route_partition("operation", reservation.operation_id, create=True)
                for reservation in reservations
            )
        )
        assert shard is not None and channel_route is not None
        assert transport_route is not None and all(route is not None for route in operation_routes)
        lock_entries = [
            self._route_lock_entry(channel_route),
            self._route_lock_entry(transport_route),
            *(self._route_lock_entry(route) for route in operation_routes if route is not None),
            self._owner_lock_entry(shard),
        ]
        replacement_route = None
        if token.replacement_channel_id:
            replacement_route = self._route_partition(
                "channel",
                token.replacement_channel_id,
                create=False,
            )
            if replacement_route is not None:
                lock_entries.append(self._route_lock_entry(replacement_route))
        with _acquire_stable_locks(lock_entries):
            if token.replacement_channel_id:
                assert token._channel_handle is not None
                replacement = shard.channels.get_by_handle(token._channel_handle)
                assert token.replacement_closed_at is not None
                self._close_locked(
                    shard,
                    token._channel_handle,
                    replacement,
                    token.replacement_closed_at,
                    token.replacement_reason,
                )
            affinity_size = shard.channels.count_prepared_affinity(prepared_identity)
            channel_handle = shard.channels.insert(
                completed,
                prepared_identity=prepared_identity,
            )
            used_id_keys = tuple(
                (channel_handle, reservation.operation_id) for reservation in reservations
            )
            for used_id_key in used_id_keys:
                shard.used_operation_ids[used_id_key] = channel_handle
            locator = self._pack_channel_locator(token._owner_shard_id, channel_handle)
            channel_route.channels.set_digest(
                self._route_digest(channel_route.channels, identity.channel_id),
                locator,
            )
            transport_route.transports.set_digest(
                self._route_digest(
                    transport_route.transports,
                    identity.binding.transport_id,
                ),
                locator,
            )
            shard.estimated_value_bytes += shard.channels.estimated_row_bytes(channel_handle) + sum(
                _used_id_estimated_bytes(key) for key in used_id_keys
            )
            shard.mutation_version += 1
            if token.kind in {"open_completed_close", "open_completed_batch_close"}:
                assert token.channel_closed_at is not None and completed.closed_at is not None
                shard.closed_expiry.set(
                    channel_handle,
                    (completed.closed_at + self._closed_grace).timestamp(),
                )
            else:
                self._set_active_deadline(shard, channel_handle, completed)
                shard.open_channels += 1
            shard.maximum_affinity_bucket = max(
                shard.maximum_affinity_bucket,
                affinity_size + 1,
            )
            shard.high_water_mark = max(shard.high_water_mark, len(shard.channels))
            close_token = (
                None
                if token.kind in {"open_completed_close", "open_completed_batch_close"}
                else ApplicationChannelCloseToken(
                    locator=locator,
                    generation=shard.channels.generation(channel_handle),
                )
            )
            return ApplicationChannelAdmissionResult(completed, close_token)

    def _commit_recoverable_open_locked(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> ApplicationChannelAdmissionResult:
        """Converge one fresh recoverable open after any primitive lost return."""

        identity = token.identity
        completed = token._prepared_snapshot
        if (
            identity is None
            or completed is None
            or token.kind
            not in {
                "open_completed",
                "open_completed_batch_close",
            }
            or token.replacement_channel_id
            or (token.channel_closed_at is not None and token.kind != "open_completed_batch_close")
        ):
            raise StateError("Recoverable application open has an unsupported mutation shape")
        journal = self._prepared_commit_journals.get(token._reservation_id)
        if journal is None:
            journal = _ApplicationChannelCommitJournal(token._reservation_id)
            self._prepared_commit_journals[token._reservation_id] = journal
        prepared_identity = _PackedChannelStore.prepare_identity(identity)
        shard = self._owner_shard(token._owner_shard_id, create=True)
        channel_route = self._route_partition("channel", identity.channel_id, create=True)
        transport_route = self._route_partition(
            "transport",
            identity.binding.transport_id,
            create=True,
        )
        reservations = token.reservations or (token.reservation,)
        terminal_batch = token.kind == "open_completed_batch_close"
        operation_routes = (
            ()
            if terminal_batch
            else tuple(
                self._route_partition("operation", reservation.operation_id, create=True)
                for reservation in reservations
            )
        )
        assert shard is not None and channel_route is not None
        assert transport_route is not None and all(route is not None for route in operation_routes)
        with _acquire_stable_locks(
            [
                self._route_lock_entry(channel_route),
                self._route_lock_entry(transport_route),
                *(self._route_lock_entry(route) for route in operation_routes if route is not None),
                self._owner_lock_entry(shard),
            ]
        ):
            if journal.initial_affinity_size is None:
                journal.initial_affinity_size = shard.channels.count_prepared_affinity(
                    prepared_identity
                )
            channel_handle = journal.channel_handle
            if channel_handle is None and journal.insert_attempted:
                channel_handle = shard.channels.recovery_handle_for_channel(
                    identity.owner_id,
                    identity.channel_id,
                )
            if channel_handle is None:
                journal.insert_attempted = True
                channel_handle = shard.channels.insert(
                    completed,
                    prepared_identity=prepared_identity,
                )
            journal.channel_handle = channel_handle
            journal.channel_generation = shard.channels.generation(channel_handle)
            if shard.channels.detached_by_handle(channel_handle) != completed:
                raise StateError("Recoverable application open row is not its exact poststate")
            self._prepared_commit_fault("open-row")

            used_id_keys = tuple(
                (channel_handle, reservation.operation_id) for reservation in reservations
            )
            for used_id_key in used_id_keys:
                if used_id_key not in shard.used_operation_ids:
                    shard.used_operation_ids[used_id_key] = channel_handle
            self._prepared_commit_fault("open-operation-marker")

            locator = self._pack_channel_locator(token._owner_shard_id, channel_handle)
            self._ensure_route_value(
                channel_route.channels,
                identity.channel_id,
                locator,
            )
            self._prepared_commit_fault("open-channel-route")
            self._ensure_route_value(
                transport_route.transports,
                identity.binding.transport_id,
                locator,
            )
            self._prepared_commit_fault("open-transport-route")

            active_deadline = self._effective_deadline(completed).timestamp()
            if terminal_batch:
                assert completed.closed_at is not None
                self._ensure_expiry_value(shard.active_expiry, channel_handle, None)
                self._ensure_expiry_value(shard.operation_blocker_expiry, channel_handle, None)
                self._ensure_expiry_value(
                    shard.closed_expiry,
                    channel_handle,
                    (completed.closed_at + self._closed_grace).timestamp(),
                )
            else:
                self._ensure_expiry_value(shard.active_expiry, channel_handle, active_deadline)
                self._ensure_expiry_value(shard.operation_blocker_expiry, channel_handle, None)
                self._ensure_expiry_value(shard.closed_expiry, channel_handle, None)
            self._prepared_commit_fault("open-expiry")

            self._apply_prepared_accounting(
                shard,
                journal,
                estimated_delta=(
                    shard.channels.estimated_row_bytes(channel_handle)
                    + sum(_used_id_estimated_bytes(key) for key in used_id_keys)
                ),
                mutation_delta=1,
                open_delta=0 if terminal_batch else 1,
                minimum_affinity_bucket=(
                    journal.initial_affinity_size
                    if terminal_batch
                    else (journal.initial_affinity_size or 0) + 1
                ),
                minimum_high_water_mark=len(shard.channels),
                stage="open-accounting",
            )
            self._prepared_commit_fault("open-accounting")

            if (
                self._route_locator(channel_route.channels, identity.channel_id) != locator
                or self._route_locator(
                    transport_route.transports,
                    identity.binding.transport_id,
                )
                != locator
                or any(key not in shard.used_operation_ids for key in used_id_keys)
                or (
                    not terminal_batch
                    and shard.active_expiry.get(channel_handle) != active_deadline
                )
                or (
                    terminal_batch
                    and (
                        shard.active_expiry.get(channel_handle) is not None
                        or completed.closed_at is None
                        or shard.closed_expiry.get(channel_handle)
                        != (completed.closed_at + self._closed_grace).timestamp()
                    )
                )
                or (not terminal_batch and shard.closed_expiry.get(channel_handle) is not None)
            ):
                raise StateError("Recoverable application open poststate is incomplete")
            generation = journal.channel_generation
            if generation is None:
                raise StateError("Recoverable application open lost its handle generation")
            close_token = (
                None
                if terminal_batch
                else ApplicationChannelCloseToken(
                    locator=locator,
                    generation=generation,
                )
            )
            return ApplicationChannelAdmissionResult(completed, close_token)

    def _commit_prepared_operation_locked(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> ApplicationChannelAdmissionResult:
        """Perform primitive immediate-operation writes after claim validation."""

        if token._retain_result_for_recovery:
            return self._commit_recoverable_operation_locked(token)

        channel_handle = token._channel_handle
        updated = token._prepared_snapshot
        snapshot = token._expected_snapshot
        assert channel_handle is not None and updated is not None and snapshot is not None
        shard = self._owner_shard(token._owner_shard_id, create=False)
        assert shard is not None
        channel_route = self._route_partition(
            "channel",
            token.reservation.channel_id,
            create=False,
        )
        operation_route = self._route_partition(
            "operation",
            token.reservation.operation_id,
            create=True,
        )
        assert channel_route is not None and operation_route is not None
        with _acquire_stable_locks(
            [
                self._route_lock_entry(channel_route),
                self._route_lock_entry(operation_route),
                self._owner_lock_entry(shard),
            ]
        ):
            used_id_key = (channel_handle, token.reservation.operation_id)
            shard.used_operation_ids[used_id_key] = channel_handle
            shard.channels.replace(channel_handle, updated, known_prior=snapshot)
            shard.estimated_value_bytes += (
                _snapshot_estimated_bytes(updated)
                - _snapshot_estimated_bytes(snapshot)
                + _used_id_estimated_bytes(used_id_key)
            )
            shard.mutation_version += 1
            if token.kind == "completed_operation_close":
                assert token.channel_closed_at is not None and updated.closed_at is not None
                shard.active_expiry.pop(channel_handle, None)
                shard.operation_blocker_expiry.pop(channel_handle, None)
                shard.closed_expiry.set(
                    channel_handle,
                    (updated.closed_at + self._closed_grace).timestamp(),
                )
                shard.open_channels -= 1
            else:
                self._set_active_deadline(shard, channel_handle, updated)
                if updated.active_operations:
                    shard.operation_blocker_expiry.set(
                        channel_handle,
                        self._effective_deadline(updated).timestamp(),
                    )
                else:
                    shard.operation_blocker_expiry.pop(channel_handle, None)
            return ApplicationChannelAdmissionResult(updated)

    def _commit_recoverable_operation_locked(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> ApplicationChannelAdmissionResult:
        """Converge one completed operation without double-applying accounting."""

        channel_handle = token._channel_handle
        updated = token._prepared_snapshot
        snapshot = token._expected_snapshot
        if (
            channel_handle is None
            or updated is None
            or snapshot is None
            or token.kind != "completed_operation"
            or token.channel_closed_at is not None
        ):
            raise StateError("Recoverable application operation has an unsupported shape")
        journal = self._prepared_commit_journals.get(token._reservation_id)
        if journal is None:
            journal = _ApplicationChannelCommitJournal(
                token._reservation_id,
                channel_handle=channel_handle,
                channel_generation=token._channel_generation,
            )
            self._prepared_commit_journals[token._reservation_id] = journal
        shard = self._owner_shard(token._owner_shard_id, create=False)
        channel_route = self._route_partition(
            "channel",
            token.reservation.channel_id,
            create=False,
        )
        operation_route = self._route_partition(
            "operation",
            token.reservation.operation_id,
            create=True,
        )
        if shard is None or channel_route is None or operation_route is None:
            raise StateError("Recoverable application operation owner disappeared")
        with _acquire_stable_locks(
            [
                self._route_lock_entry(channel_route),
                self._route_lock_entry(operation_route),
                self._owner_lock_entry(shard),
            ]
        ):
            locator = self._pack_channel_locator(token._owner_shard_id, channel_handle)
            if self._route_locator(
                channel_route.channels,
                token.reservation.channel_id,
            ) != locator or not shard.channels.matches(
                channel_handle,
                token._channel_generation or 0,
                token.reservation.channel_id,
            ):
                raise StateError("Recoverable application operation channel changed")

            used_id_key = (channel_handle, token.reservation.operation_id)
            if used_id_key not in shard.used_operation_ids:
                shard.used_operation_ids[used_id_key] = channel_handle
            self._prepared_commit_fault("operation-marker")

            current = shard.channels.detached_by_handle(channel_handle)
            if current == snapshot:
                shard.channels.replace(channel_handle, updated, known_prior=snapshot)
            elif current != updated:
                raise StateError("Recoverable application operation row is indeterminate")
            self._prepared_commit_fault("operation-row")

            active_deadline = self._effective_deadline(updated).timestamp()
            self._ensure_expiry_value(shard.active_expiry, channel_handle, active_deadline)
            self._ensure_expiry_value(
                shard.operation_blocker_expiry,
                channel_handle,
                active_deadline if updated.active_operations else None,
            )
            self._ensure_expiry_value(shard.closed_expiry, channel_handle, None)
            self._prepared_commit_fault("operation-expiry")

            self._apply_prepared_accounting(
                shard,
                journal,
                estimated_delta=(
                    _snapshot_estimated_bytes(updated)
                    - _snapshot_estimated_bytes(snapshot)
                    + _used_id_estimated_bytes(used_id_key)
                ),
                mutation_delta=1,
                stage="operation-accounting",
            )
            self._prepared_commit_fault("operation-accounting")

            if (
                shard.channels.detached_by_handle(channel_handle) != updated
                or used_id_key not in shard.used_operation_ids
                or shard.active_expiry.get(channel_handle) != active_deadline
                or shard.closed_expiry.get(channel_handle) is not None
            ):
                raise StateError("Recoverable application operation poststate is incomplete")
            return ApplicationChannelAdmissionResult(updated)

    def open_channel(self, identity: ApplicationChannelIdentity) -> ApplicationChannelSnapshot:
        """Open one channel through stable exact route and owner-shard locks."""

        # Route partitions are lazy and may be reclaimed at a watermark.  Take
        # mutation admission before resolving them so a waiting opener cannot
        # retain an empty partition that the watermark subsequently retires.
        with (
            self._gate.mutation(),
            self._ordinary_mutation_admission(
                channel_ids=(identity.channel_id,),
                transport_ids=(identity.binding.transport_id,),
                affinity_key=(identity.owner_id, identity.affinity_digest),
            ),
        ):
            snapshot, _token = self._open_channel_admitted(identity)
            return snapshot

    def open_channel_with_token(
        self,
        identity: ApplicationChannelIdentity,
    ) -> tuple[ApplicationChannelSnapshot, ApplicationChannelCloseToken]:
        """Open one channel and return its close token without a second lookup."""

        with (
            self._gate.mutation(),
            self._ordinary_mutation_admission(
                channel_ids=(identity.channel_id,),
                transport_ids=(identity.binding.transport_id,),
                affinity_key=(identity.owner_id, identity.affinity_digest),
            ),
        ):
            return self._open_channel_admitted(identity)

    def _open_channel_admitted(
        self,
        identity: ApplicationChannelIdentity,
    ) -> tuple[ApplicationChannelSnapshot, ApplicationChannelCloseToken]:
        """Open one channel after mutation admission has fenced watermarks."""

        prepared_identity = _PackedChannelStore.prepare_identity(identity)
        owner_shard_id = self._owner_shard_id(identity.owner_id)
        shard = self._owner_shard(owner_shard_id, create=True)
        channel_route = self._route_partition("channel", identity.channel_id, create=True)
        transport_route = self._route_partition(
            "transport", identity.binding.transport_id, create=True
        )
        assert shard is not None and channel_route is not None and transport_route is not None
        lock_entries = [
            self._route_lock_entry(channel_route),
            self._route_lock_entry(transport_route),
            self._owner_lock_entry(shard),
        ]
        with _acquire_stable_locks(lock_entries):
            opened_at = self._require_window_time(identity.opened_at, "channel opened_at")
            if opened_at < self._watermark:
                raise StateError("Application channels cannot open before the current watermark")
            if identity.hard_deadline > self._window_end:
                raise StateError("Application channel hard_deadline must be inside the window")
            channel_digest = self._route_digest(channel_route.channels, identity.channel_id)
            transport_digest = self._route_digest(
                transport_route.transports,
                identity.binding.transport_id,
            )
            if channel_route.channels.get_digest(channel_digest) is not None:
                raise StateError(f"Duplicate application channel_id {identity.channel_id!r}")
            retained_transport = transport_route.transports.get_digest(transport_digest)
            if retained_transport is not None:
                raise StateError(
                    f"Transport {identity.binding.transport_id!r} already owns open channel or "
                    "retained channel"
                )

            affinity_key = (identity.owner_id, identity.affinity_digest)
            affinity_size = shard.channels.count_prepared_affinity(prepared_identity) + len(
                self._prepared_affinity_reservations.get(affinity_key, ())
            )
            if affinity_size >= self._max_reusable_per_affinity:
                raise StateError(
                    f"Application affinity {identity.affinity_digest!r} already retains "
                    f"{affinity_size} reusable channels; limit is "
                    f"{self._max_reusable_per_affinity}"
                )

            idle_deadline = min(opened_at + identity.idle_timeout, identity.hard_deadline)
            snapshot = ApplicationChannelSnapshot(
                identity=identity,
                last_activity_at=opened_at,
                idle_deadline=idle_deadline,
            )
            channel_handle = shard.channels.insert(
                snapshot,
                prepared_identity=prepared_identity,
            )
            locator = self._pack_channel_locator(owner_shard_id, channel_handle)
            channel_route.channels.set_digest(channel_digest, locator)
            transport_route.transports.set_digest(transport_digest, locator)
            shard.estimated_value_bytes += shard.channels.estimated_row_bytes(channel_handle)
            shard.mutation_version += 1
            self._set_active_deadline(shard, channel_handle, snapshot)
            shard.open_channels += 1
            shard.maximum_affinity_bucket = max(
                shard.maximum_affinity_bucket,
                affinity_size + 1,
            )
            shard.high_water_mark = max(shard.high_water_mark, len(shard.channels))
            return snapshot, ApplicationChannelCloseToken(
                locator=locator,
                generation=shard.channels.generation(channel_handle),
            )

    def open_channel_with_completed_operation(
        self,
        identity: ApplicationChannelIdentity,
        reservation: ApplicationOperationReservation,
    ) -> ApplicationChannelSnapshot:
        """Open with one completed operation while retaining legacy return shape."""

        snapshot, _token = self.open_channel_with_completed_operation_and_token(
            identity,
            reservation,
        )
        return snapshot

    def open_channel_with_completed_operation_and_token(
        self,
        identity: ApplicationChannelIdentity,
        reservation: ApplicationOperationReservation,
        *,
        trusted_owner_partition_id: int | None = None,
    ) -> tuple[ApplicationChannelSnapshot, ApplicationChannelCloseToken]:
        """Atomically open a channel with one already-completed first operation.

        No active operation row or duration-wide operation route is published.
        A validation failure leaves no channel, transport binding, used-ID
        marker, or expiry entry behind.
        """

        if reservation.channel_id != identity.channel_id:
            raise StateError("Initial application operation must target the channel being opened")
        if reservation.parent_operation_id:
            raise StateError("Initial completed application operation cannot have a parent")
        if trusted_owner_partition_id is not None and not (
            0 <= trusted_owner_partition_id < self._shard_count
        ):
            raise ValueError("Trusted application owner partition is outside the registry")
        prepared_identity = _PackedChannelStore.prepare_identity(identity)
        self._gate.enter_mutation()
        try:
            self._begin_ordinary_fresh_open_admission(identity, reservation)
        except BaseException:
            self._gate.exit_mutation()
            raise
        try:
            owner_shard_id = (
                self._owner_shard_id(identity.owner_id)
                if trusted_owner_partition_id is None
                else trusted_owner_partition_id
            )
            shard = self._owner_shard(owner_shard_id, create=True)
            channel_route = self._route_partition("channel", identity.channel_id, create=True)
            transport_route = self._route_partition(
                "transport",
                identity.binding.transport_id,
                create=True,
            )
            operation_route = self._route_partition(
                "operation",
                reservation.operation_id,
                create=False,
            )
            assert shard is not None and channel_route is not None and transport_route is not None
            with _acquire_open_locks(
                channel_route,
                transport_route,
                operation_route,
                shard,
            ):
                opened_at = self._require_window_time(identity.opened_at, "channel opened_at")
                if opened_at < self._watermark:
                    raise StateError(
                        "Application channels cannot open before the current watermark"
                    )
                if identity.hard_deadline > self._window_end:
                    raise StateError("Application channel hard_deadline must be inside the window")
                channel_digest = self._route_digest(channel_route.channels, identity.channel_id)
                transport_digest = self._route_digest(
                    transport_route.transports,
                    identity.binding.transport_id,
                )
                if channel_route.channels.get_digest(channel_digest) is not None:
                    raise StateError(f"Duplicate application channel_id {identity.channel_id!r}")
                retained_transport = transport_route.transports.get_digest(transport_digest)
                if retained_transport is not None:
                    raise StateError(
                        f"Transport {identity.binding.transport_id!r} already owns open channel "
                        "or retained channel"
                    )
                if (
                    operation_route is not None
                    and reservation.operation_id in operation_route.operations
                ):
                    raise StateError(f"Duplicate active operation_id {reservation.operation_id!r}")
                affinity_key = (identity.owner_id, identity.affinity_digest)
                affinity_size = shard.channels.count_prepared_affinity(prepared_identity) + len(
                    self._prepared_affinity_reservations.get(affinity_key, ())
                )
                if affinity_size >= self._max_reusable_per_affinity:
                    raise StateError(
                        f"Application affinity {identity.affinity_digest!r} already retains "
                        f"{affinity_size} reusable channels; limit is "
                        f"{self._max_reusable_per_affinity}"
                    )
                completed = self._initial_completed_snapshot(identity, reservation)
                channel_handle = shard.channels.insert(
                    completed,
                    prepared_identity=prepared_identity,
                )
                used_id_key = (channel_handle, reservation.operation_id)
                try:
                    shard.used_operation_ids[used_id_key] = channel_handle
                except (KeyError, OverflowError, StateError):
                    shard.channels.delete(channel_handle)
                    raise
                locator = self._pack_channel_locator(owner_shard_id, channel_handle)
                channel_route.channels.set_digest(channel_digest, locator)
                transport_route.transports.set_digest(transport_digest, locator)
                shard.estimated_value_bytes += shard.channels.estimated_row_bytes(
                    channel_handle
                ) + _used_id_estimated_bytes(used_id_key)
                shard.mutation_version += 1
                self._set_active_deadline(shard, channel_handle, completed)
                shard.open_channels += 1
                shard.maximum_affinity_bucket = max(
                    shard.maximum_affinity_bucket,
                    affinity_size + 1,
                )
                shard.high_water_mark = max(shard.high_water_mark, len(shard.channels))
                return completed, ApplicationChannelCloseToken(
                    locator=locator,
                    generation=shard.channels.generation(channel_handle),
                )
        finally:
            try:
                self._end_ordinary_fresh_open_admission(identity, reservation)
            finally:
                self._gate.exit_mutation()

    def get(self, channel_id: str) -> ApplicationChannelSnapshot | None:
        """Return one retained channel through one route and owner shard."""

        route = self._route_partition("channel", channel_id, create=False)
        if route is None:
            return None
        # Route locks sort before owner locks everywhere. Keep the exact route
        # held while resolving its owner so a read needs one route probe and
        # one acquisition instead of release/reacquire/revalidate work.
        with route.lock:
            locator = self._route_locator(route.channels, channel_id)
            if locator is None:
                return None
            shard_id, channel_handle = self._unpack_channel_locator(locator)
            shard = self._owner_shard(shard_id, create=False)
            if shard is None:
                return None
            with shard.lock:
                try:
                    snapshot = shard.channels.get_by_handle(channel_handle)
                except KeyError:
                    return None
                shard.lookup_candidates_inspected += 1
                return snapshot if snapshot.channel_id == channel_id else None

    def channel_close_token(self, channel_id: str) -> ApplicationChannelCloseToken | None:
        """Return a compact ABA-safe token without reconstructing channel state."""

        routed = self._channel_route(channel_id)
        if routed is None:
            return None
        route, shard_id, channel_handle = routed
        shard = self._owner_shard(shard_id, create=False)
        if shard is None:
            return None
        locator = self._pack_channel_locator(shard_id, channel_handle)
        with _acquire_stable_locks([self._route_lock_entry(route), self._owner_lock_entry(shard)]):
            if self._route_locator(route.channels, channel_id) != locator:
                return None
            try:
                generation = shard.channels.generation(channel_handle)
            except KeyError:
                return None
            if not shard.channels.matches(channel_handle, generation, channel_id):
                return None
            return ApplicationChannelCloseToken(locator=locator, generation=generation)

    def owner_partition_for_channel(self, channel_id: str) -> int | None:
        """Return the stable owner partition routed by an exact channel ID.

        Protocol managers use this as a compact sidecar-routing hint. The
        returned partition is valid only for the current retained route; the
        protocol sidecar still verifies the full canonical channel ID after
        acquiring its own shard lock.
        """

        routed = self._channel_route(channel_id)
        return None if routed is None else routed[1]

    def find_open_by_transport(self, transport_id: str) -> ApplicationChannelSnapshot | None:
        """Return the open channel bound to an exact transport identity."""

        route = self._route_partition("transport", transport_id, create=False)
        if route is None:
            return None
        with route.lock:
            routed = self._route_locator(route.transports, transport_id)
        if routed is None:
            return None
        shard_id, channel_handle = self._unpack_channel_locator(routed)
        shard = self._owner_shard(shard_id, create=False)
        if shard is None:
            return None
        with _acquire_stable_locks([self._route_lock_entry(route), self._owner_lock_entry(shard)]):
            if self._route_locator(route.transports, transport_id) != routed:
                return None
            try:
                snapshot = shard.channels.get_by_handle(channel_handle)
            except KeyError:
                return None
            return (
                snapshot
                if snapshot.identity.binding.transport_id == transport_id and snapshot.is_open
                else None
            )

    def count_open_for_owner(self, owner_id: str) -> int:
        """Return an owner's open-channel count from its exact shard bucket."""

        shard = self._owner_shard(self._owner_shard_id(owner_id), create=False)
        if shard is None:
            return 0
        with shard.lock:
            return shard.channels.count("owner", owner_id)

    def open_owner_page(
        self,
        owner_id: str,
        *,
        limit: int,
        cursor: ApplicationChannelPageCursor | None = None,
    ) -> tuple[tuple[ApplicationChannelSnapshot, ...], ApplicationChannelPageCursor | None]:
        """Return one bounded mutation-fenced page from an exact owner bucket."""

        if limit <= 0:
            raise ValueError("Application channel page limit must be positive")
        shard_id = self._owner_shard_id(owner_id)
        shard = self._owner_shard(shard_id, create=False)
        if shard is None:
            return (), None
        with shard.lock:
            if cursor is None:
                after_handle = None
            elif (
                cursor._registry_token != id(self)
                or cursor._owner_id != owner_id
                or cursor._shard_id != shard_id
            ):
                raise StateError("Application channel page cursor belongs to another query")
            else:
                after_handle = cursor._after_handle
            if cursor is not None and cursor._mutation_version != shard.mutation_version:
                raise StateError("Application channel page cursor was invalidated by mutation")
            try:
                handles, next_handle = shard.channels.find_handle_page(
                    "owner",
                    owner_id,
                    after_handle=after_handle,
                    limit=limit,
                )
            except KeyError as exc:
                raise StateError("Application channel page cursor is stale") from exc
            page = tuple(shard.channels.get_by_handle(handle) for handle in handles)
            next_cursor = (
                ApplicationChannelPageCursor(
                    registry_token=id(self),
                    owner_id=owner_id,
                    shard_id=shard_id,
                    mutation_version=shard.mutation_version,
                    after_handle=next_handle,
                )
                if next_handle is not None
                else None
            )
            return page, next_cursor

    def find_reusable(
        self,
        *,
        affinity_digest: str,
        owner_id: str,
        at: datetime,
    ) -> ApplicationChannelSnapshot | None:
        """Return the best exact owner-affinity candidate after bounded inspection."""

        canonical_time = self._require_window_time(at, "reuse time")
        shard = self._owner_shard(self._owner_shard_id(owner_id), create=False)
        if shard is None:
            return None
        affinity_key = (owner_id, affinity_digest.strip().casefold())
        with shard.lock:
            candidates = tuple(shard.channels.find_iter("affinity", affinity_key))
            if len(candidates) > self._max_reusable_per_affinity:
                raise StateError("Application affinity index exceeded its configured bound")
            eligible: list[ApplicationChannelSnapshot] = []
            for candidate in candidates:
                shard.lookup_candidates_inspected += 1
                if self._is_reusable_at(candidate, canonical_time):
                    eligible.append(candidate)
            if not eligible:
                return None
            return max(eligible, key=lambda item: (item.last_activity_at, item.channel_id))

    def _updated_for_operation(
        self,
        snapshot: ApplicationChannelSnapshot,
        reservation: ApplicationOperationReservation,
        *,
        completes_immediately: bool,
    ) -> ApplicationChannelSnapshot:
        """Validate one operation and return its aggregate channel outcome."""

        if reservation.ordinal != snapshot.reserved_operations:
            raise StateError(
                f"Operation {reservation.operation_id!r} ordinal {reservation.ordinal} does "
                f"not match next channel ordinal {snapshot.reserved_operations}"
            )
        if not snapshot.is_open:
            raise StateError(f"Application channel {reservation.channel_id!r} is closed")
        if reservation.started_at < self._watermark:
            raise StateError("Application operations cannot start before the current watermark")
        self._require_window_time(reservation.started_at, "operation started_at")
        self._require_window_time(
            reservation.ended_at,
            "operation ended_at",
            allow_end_boundary=True,
        )
        deadline = self._effective_deadline(snapshot)
        if reservation.started_at >= deadline:
            raise StateError(
                f"Operation {reservation.operation_id!r} starts at or after channel expiry"
            )
        if (
            reservation.started_at < snapshot.identity.opened_at
            or reservation.ended_at > snapshot.identity.hard_deadline
            or reservation.ended_at > snapshot.identity.binding.closes_at
        ):
            raise StateError(
                f"Operation {reservation.operation_id!r} is outside its channel or transport"
            )
        budget = snapshot.identity.budget
        initiator_total = snapshot.reserved_initiator_bytes + reservation.initiator_bytes
        responder_total = snapshot.reserved_responder_bytes + reservation.responder_bytes
        operation_total = snapshot.reserved_operations + 1
        if initiator_total > budget.initiator_bytes:
            raise StateError("Application operation exceeds the initiator byte budget")
        if responder_total > budget.responder_bytes:
            raise StateError("Application operation exceeds the responder byte budget")
        if operation_total > budget.operations:
            raise StateError("Application operation exceeds the channel operation budget")
        idle_deadline = min(
            reservation.ended_at + snapshot.identity.idle_timeout,
            snapshot.identity.hard_deadline,
            snapshot.identity.binding.closes_at,
        )
        return replace(
            snapshot,
            last_activity_at=max(snapshot.last_activity_at, reservation.ended_at),
            idle_deadline=max(snapshot.idle_deadline, idle_deadline),
            reserved_initiator_bytes=initiator_total,
            reserved_responder_bytes=responder_total,
            reserved_operations=operation_total,
            completed_operations=(
                snapshot.completed_operations + 1
                if completes_immediately
                else snapshot.completed_operations
            ),
            active_operations=(
                snapshot.active_operations
                if completes_immediately
                else snapshot.active_operations + 1
            ),
        )

    def _initial_completed_snapshot(
        self,
        identity: ApplicationChannelIdentity,
        reservation: ApplicationOperationReservation,
    ) -> ApplicationChannelSnapshot:
        """Validate and pack an already-completed first operation in one value build."""

        if reservation.ordinal != 0:
            raise StateError(
                f"Operation {reservation.operation_id!r} ordinal {reservation.ordinal} does "
                "not match next channel ordinal 0"
            )
        if reservation.started_at < self._watermark:
            raise StateError("Application operations cannot start before the current watermark")
        self._require_window_time(reservation.started_at, "operation started_at")
        self._require_window_time(
            reservation.ended_at,
            "operation ended_at",
            allow_end_boundary=True,
        )
        initial_idle_deadline = min(
            identity.opened_at + identity.idle_timeout, identity.hard_deadline
        )
        if reservation.started_at >= initial_idle_deadline:
            raise StateError(
                f"Operation {reservation.operation_id!r} starts at or after channel expiry"
            )
        if (
            reservation.started_at < identity.opened_at
            or reservation.ended_at > identity.hard_deadline
            or reservation.ended_at > identity.binding.closes_at
        ):
            raise StateError(
                f"Operation {reservation.operation_id!r} is outside its channel or transport"
            )
        budget = identity.budget
        if reservation.initiator_bytes > budget.initiator_bytes:
            raise StateError("Application operation exceeds the initiator byte budget")
        if reservation.responder_bytes > budget.responder_bytes:
            raise StateError("Application operation exceeds the responder byte budget")
        if budget.operations < 1:
            raise StateError("Application operation exceeds the channel operation budget")
        operation_idle_deadline = min(
            reservation.ended_at + identity.idle_timeout,
            identity.hard_deadline,
            identity.binding.closes_at,
        )
        return cast(
            ApplicationChannelSnapshot,
            _PackedChannelStore._new_value(
                ApplicationChannelSnapshot,
                identity=identity,
                last_activity_at=max(identity.opened_at, reservation.ended_at),
                idle_deadline=max(initial_idle_deadline, operation_idle_deadline),
                reserved_initiator_bytes=reservation.initiator_bytes,
                reserved_responder_bytes=reservation.responder_bytes,
                reserved_operations=1,
                completed_operations=1,
                active_operations=0,
                closed_at=None,
                close_reason="",
            ),
        )

    def reserve_operation(
        self,
        reservation: ApplicationOperationReservation,
    ) -> ApplicationChannelSnapshot:
        """Atomically reserve one contained span and directional capacity."""

        # Operation routes are lazy just like channel/transport routes.  Keep
        # the admission lease across route resolution and insertion so an
        # empty route partition cannot be reclaimed between those two steps.
        with (
            self._gate.mutation(),
            self._ordinary_mutation_admission(
                channel_ids=(reservation.channel_id,),
                operation_ids=(reservation.operation_id,),
            ),
        ):
            return self._reserve_operation_admitted(reservation)

    def _reserve_operation_admitted(
        self,
        reservation: ApplicationOperationReservation,
    ) -> ApplicationChannelSnapshot:
        """Reserve an operation after mutation admission has fenced watermarks."""

        routed = self._channel_route(reservation.channel_id)
        if routed is None:
            raise StateError(
                f"Unknown application channel {reservation.channel_id!r} for operation "
                f"{reservation.operation_id!r}"
            )
        channel_route, shard_id, channel_handle = routed
        shard = self._owner_shard(shard_id, create=False)
        operation_route = self._route_partition("operation", reservation.operation_id, create=True)
        assert shard is not None and operation_route is not None
        lock_entries = [
            self._route_lock_entry(channel_route),
            self._route_lock_entry(operation_route),
            self._owner_lock_entry(shard),
        ]
        with _acquire_stable_locks(lock_entries):
            locator = self._pack_channel_locator(shard_id, channel_handle)
            if self._route_locator(channel_route.channels, reservation.channel_id) != locator:
                raise StateError(f"Unknown application channel {reservation.channel_id!r}")
            try:
                snapshot = shard.channels.get_by_handle(channel_handle)
            except KeyError:
                raise StateError(
                    f"Unknown application channel {reservation.channel_id!r}"
                ) from None
            if snapshot.channel_id != reservation.channel_id:
                raise StateError(f"Unknown application channel {reservation.channel_id!r}")
            if reservation.operation_id in operation_route.operations:
                raise StateError(f"Duplicate active operation_id {reservation.operation_id!r}")
            used_id_key = (channel_handle, reservation.operation_id)
            if used_id_key in shard.used_operation_ids:
                raise StateError(
                    f"Operation_id {reservation.operation_id!r} was already used by channel "
                    f"{reservation.channel_id!r}"
                )
            if reservation.parent_operation_id:
                parent = shard.operations.get(reservation.parent_operation_id)
                if parent is None:
                    raise StateError(
                        f"Operation {reservation.operation_id!r} references inactive parent "
                        f"{reservation.parent_operation_id!r}"
                    )
                if parent.channel_id != reservation.channel_id:
                    raise StateError("Application child operation must share its parent's channel")
                if (
                    reservation.started_at < parent.started_at
                    or reservation.ended_at > parent.ended_at
                ):
                    raise StateError(
                        f"Operation {reservation.operation_id!r} is not contained by parent "
                        f"{parent.operation_id!r}"
                    )
            updated = self._updated_for_operation(
                snapshot,
                reservation,
                completes_immediately=False,
            )
            shard.used_operation_ids[used_id_key] = channel_handle
            shard.operations[reservation.operation_id] = reservation
            operation_route.operations[reservation.operation_id] = locator
            shard.channels.replace(channel_handle, updated, known_prior=snapshot)
            shard.estimated_value_bytes += (
                _snapshot_estimated_bytes(updated)
                - _snapshot_estimated_bytes(snapshot)
                + _operation_estimated_bytes(reservation)
                + _used_id_estimated_bytes(used_id_key)
            )
            shard.mutation_version += 1
            self._set_active_deadline(shard, channel_handle, updated)
            shard.operation_blocker_expiry.set(
                channel_handle,
                self._effective_deadline(updated).timestamp(),
            )
            return updated

    def reserve_completed_operation(
        self,
        reservation: ApplicationOperationReservation,
    ) -> ApplicationChannelSnapshot:
        """Atomically reconcile one operation without publishing active state.

        This path is for synchronous protocol children whose completion is
        already known at admission. It performs the same containment, budget,
        ordinal, and operation-ID checks as ``reserve_operation`` followed by
        ``finalize_operation``, but retains only the compact used-ID marker and
        aggregate channel outcome.
        """

        with (
            self._gate.mutation(),
            self._ordinary_mutation_admission(
                channel_ids=(reservation.channel_id,),
                operation_ids=(reservation.operation_id,),
            ),
        ):
            routed = self._channel_route(reservation.channel_id)
            if routed is None:
                raise StateError(
                    f"Unknown application channel {reservation.channel_id!r} for operation "
                    f"{reservation.operation_id!r}"
                )
            channel_route, shard_id, channel_handle = routed
            shard = self._owner_shard(shard_id, create=False)
            operation_route = self._route_partition(
                "operation",
                reservation.operation_id,
                create=True,
            )
            assert shard is not None and operation_route is not None
            lock_entries = [
                self._route_lock_entry(channel_route),
                self._route_lock_entry(operation_route),
                self._owner_lock_entry(shard),
            ]
            with _acquire_stable_locks(lock_entries):
                locator = self._pack_channel_locator(shard_id, channel_handle)
                if self._route_locator(channel_route.channels, reservation.channel_id) != locator:
                    raise StateError(f"Unknown application channel {reservation.channel_id!r}")
                try:
                    snapshot = shard.channels.get_by_handle(channel_handle)
                except KeyError:
                    raise StateError(
                        f"Unknown application channel {reservation.channel_id!r}"
                    ) from None
                if snapshot.channel_id != reservation.channel_id:
                    raise StateError(f"Unknown application channel {reservation.channel_id!r}")
                if reservation.operation_id in operation_route.operations:
                    raise StateError(f"Duplicate active operation_id {reservation.operation_id!r}")
                used_id_key = (channel_handle, reservation.operation_id)
                if used_id_key in shard.used_operation_ids:
                    raise StateError(
                        f"Operation_id {reservation.operation_id!r} was already used by channel "
                        f"{reservation.channel_id!r}"
                    )
                if reservation.parent_operation_id:
                    parent = shard.operations.get(reservation.parent_operation_id)
                    if parent is None:
                        raise StateError(
                            f"Operation {reservation.operation_id!r} references inactive parent "
                            f"{reservation.parent_operation_id!r}"
                        )
                    if parent.channel_id != reservation.channel_id:
                        raise StateError(
                            "Application child operation must share its parent's channel"
                        )
                    if (
                        reservation.started_at < parent.started_at
                        or reservation.ended_at > parent.ended_at
                    ):
                        raise StateError(
                            f"Operation {reservation.operation_id!r} is not contained by parent "
                            f"{parent.operation_id!r}"
                        )
                updated = self._updated_for_operation(
                    snapshot,
                    reservation,
                    completes_immediately=True,
                )
                shard.used_operation_ids[used_id_key] = channel_handle
                shard.channels.replace(
                    channel_handle,
                    updated,
                    known_prior=snapshot,
                )
                shard.estimated_value_bytes += (
                    _snapshot_estimated_bytes(updated)
                    - _snapshot_estimated_bytes(snapshot)
                    + _used_id_estimated_bytes(used_id_key)
                )
                shard.mutation_version += 1
                self._set_active_deadline(shard, channel_handle, updated)
                if updated.active_operations:
                    shard.operation_blocker_expiry.set(
                        channel_handle,
                        self._effective_deadline(updated).timestamp(),
                    )
                else:
                    shard.operation_blocker_expiry.pop(channel_handle, None)
                return updated

    def finalize_operation(self, operation_id: str) -> bool:
        """Finalize one active operation; repeated finalization is a no-op."""

        with self._gate.mutation():
            routed = self._operation_route(operation_id)
            if routed is None:
                return False
            operation_route, shard_id, channel_handle = routed
            shard = self._owner_shard(shard_id, create=False)
            if shard is None:
                return False
            locks = [self._route_lock_entry(operation_route), self._owner_lock_entry(shard)]
            with _acquire_stable_locks(locks):
                locator = self._pack_channel_locator(shard_id, channel_handle)
                if operation_route.operations.get(operation_id) != locator:
                    return False
                operation = shard.operations.get(operation_id)
                if operation is None:
                    return False
                channel_id = operation.channel_id
            with (
                self._ordinary_mutation_admission(
                    channel_ids=(channel_id,),
                    operation_ids=(operation_id,),
                ),
                _acquire_stable_locks(locks),
            ):
                locator = self._pack_channel_locator(shard_id, channel_handle)
                if operation_route.operations.get(operation_id) != locator:
                    return False
                operation = shard.operations.get(operation_id)
                if operation is None or operation.channel_id != channel_id:
                    return False
                if shard.operations.count("parent", operation_id):
                    raise StateError(
                        f"Application operation {operation_id!r} still owns active child operations"
                    )
                try:
                    snapshot = shard.channels.get_by_handle(channel_handle)
                except KeyError:
                    return False
                if snapshot.channel_id != operation.channel_id:
                    return False
                del shard.operations[operation_id]
                if operation_route.operations.pop(operation_id, None) is not None:
                    operation_route.operation_deletions += 1
                shard.operation_deletions += 1
                updated = replace(
                    snapshot,
                    completed_operations=snapshot.completed_operations + 1,
                    active_operations=snapshot.active_operations - 1,
                )
                shard.channels.replace(channel_handle, updated, known_prior=snapshot)
                shard.estimated_value_bytes += (
                    _snapshot_estimated_bytes(updated)
                    - _snapshot_estimated_bytes(snapshot)
                    - _operation_estimated_bytes(operation)
                )
                shard.mutation_version += 1
                if updated.active_operations:
                    shard.operation_blocker_expiry.set(
                        channel_handle,
                        self._effective_deadline(updated).timestamp(),
                    )
                else:
                    shard.operation_blocker_expiry.pop(channel_handle, None)
                return True

    def _close_handle_locked(
        self,
        shard: _ApplicationChannelShard,
        channel_handle: int,
        *,
        generation: int,
        channel_id: str,
        closed_at: datetime,
        reason: str,
        include_retirement_proof: bool = False,
    ) -> ApplicationChannelCloseResult:
        """Commit one validated primitive close while the owner lock is held."""

        newly_closed, authoritative_us = shard.channels.close_primitive(
            channel_handle,
            generation=generation,
            channel_id=channel_id,
            closed_at_us=_datetime_us(closed_at),
            reason=reason,
        )
        authoritative_time = _datetime_from_us(authoritative_us)
        if newly_closed:
            shard.active_expiry.pop(channel_handle, None)
            shard.operation_blocker_expiry.pop(channel_handle, None)
            shard.mutation_version += 1
            shard.closed_expiry.set(
                channel_handle,
                (authoritative_time + self._closed_grace).timestamp(),
            )
            shard.open_channels -= 1
        retirement_proof = None
        if include_retirement_proof:
            terminal = shard.channels.detached_by_handle(channel_handle)
            retirement_proof = self._retirement_proof_for_snapshot(terminal)
        return ApplicationChannelCloseResult(
            channel_id=channel_id,
            closed_at=authoritative_time,
            newly_closed=newly_closed,
            retirement_proof=retirement_proof,
        )

    def _close_channel_by_token_admitted(
        self,
        channel_id: str,
        *,
        token: ApplicationChannelCloseToken,
        closed_at: datetime,
        reason: str,
        include_retirement_proof: bool = False,
    ) -> ApplicationChannelCloseResult:
        """Close one token after mutation admission has fenced watermarks."""

        normalized_channel_id = channel_id.strip()
        normalized_reason = reason.strip()
        if not normalized_channel_id:
            raise ValueError("Application channel close requires a channel_id")
        if not normalized_reason:
            raise StateError("Application channel closure requires a reason")
        canonical_time = self._require_window_time(
            closed_at,
            "channel closed_at",
            allow_end_boundary=True,
        )
        if canonical_time < self._watermark:
            raise StateError("Application channels cannot close before the current watermark")
        shard_id, channel_handle = self._unpack_channel_locator(token.locator)
        shard = self._owner_shard(shard_id, create=False)
        if shard is None:
            raise StateError(f"Stale application channel close token for {channel_id!r}")
        with shard.lock:
            return self._close_handle_locked(
                shard,
                channel_handle,
                generation=token.generation,
                channel_id=normalized_channel_id,
                closed_at=canonical_time,
                reason=normalized_reason,
                include_retirement_proof=include_retirement_proof,
            )

    def close_channel_by_token(
        self,
        channel_id: str,
        *,
        token: ApplicationChannelCloseToken,
        closed_at: datetime,
        reason: str,
        include_retirement_proof: bool = False,
    ) -> ApplicationChannelCloseResult:
        """Close one exact channel without reconstructing its identity or plan."""

        with self._gate.mutation(), self._ordinary_mutation_admission(channel_ids=(channel_id,)):
            return self._close_channel_by_token_admitted(
                channel_id,
                token=token,
                closed_at=closed_at,
                reason=reason,
                include_retirement_proof=include_retirement_proof,
            )

    def close_channels_by_token(
        self,
        requests: tuple[ApplicationChannelCloseRequest, ...],
        *,
        limit: int = _EXPIRY_PAGE_SIZE,
    ) -> tuple[ApplicationChannelCloseResult, ...]:
        """Close one bounded deterministic page with per-request atomicity."""

        if limit <= 0 or limit > _EXPIRY_PAGE_SIZE:
            raise ValueError(
                f"Application close-page limit must be between 1 and {_EXPIRY_PAGE_SIZE}"
            )
        if len(requests) > limit:
            raise ValueError(
                f"Application close page contains {len(requests)} requests; limit is {limit}"
            )
        prepared: list[
            tuple[
                str,
                ApplicationChannelCloseToken,
                datetime,
                str,
                _ApplicationChannelShard,
                int,
            ]
        ] = []
        normalized_channel_ids = tuple(request.channel_id.strip() for request in requests)
        with (
            self._gate.mutation(),
            self._ordinary_mutation_admission(channel_ids=normalized_channel_ids),
        ):
            for request in requests:
                channel_id = request.channel_id.strip()
                reason = request.reason.strip()
                if not channel_id:
                    raise ValueError("Application channel close requires a channel_id")
                if not reason:
                    raise StateError("Application channel closure requires a reason")
                closed_at = self._require_window_time(
                    request.closed_at,
                    "channel closed_at",
                    allow_end_boundary=True,
                )
                if closed_at < self._watermark:
                    raise StateError(
                        "Application channels cannot close before the current watermark"
                    )
                shard_id, channel_handle = self._unpack_channel_locator(request.token.locator)
                shard = self._owner_shard(shard_id, create=False)
                if shard is None:
                    raise StateError(
                        f"Stale application channel close token for {request.channel_id!r}"
                    )
                prepared.append(
                    (
                        channel_id,
                        request.token,
                        closed_at,
                        reason,
                        shard,
                        channel_handle,
                    )
                )
            lock_entries = [self._owner_lock_entry(item[4]) for item in prepared]
            results: list[ApplicationChannelCloseResult] = []
            with _acquire_stable_locks(lock_entries):
                for channel_id, token, closed_at, reason, shard, channel_handle in prepared:
                    results.append(
                        self._close_handle_locked(
                            shard,
                            channel_handle,
                            generation=token.generation,
                            channel_id=channel_id,
                            closed_at=closed_at,
                            reason=reason,
                        )
                    )
            return tuple(results)

    def close_channel(
        self,
        channel_id: str,
        *,
        closed_at: datetime,
        reason: str,
    ) -> ApplicationChannelSnapshot:
        """Finalize one channel idempotently and start compact grace retention."""

        with self._gate.mutation(), self._ordinary_mutation_admission(channel_ids=(channel_id,)):
            routed = self._channel_route(channel_id)
            if routed is None:
                raise StateError(f"Unknown application channel {channel_id!r}")
            channel_route, shard_id, channel_handle = routed
            shard = self._owner_shard(shard_id, create=False)
            if shard is None:
                raise StateError(f"Unknown application channel {channel_id!r}")
            with _acquire_stable_locks(
                [self._route_lock_entry(channel_route), self._owner_lock_entry(shard)]
            ):
                locator = self._pack_channel_locator(shard_id, channel_handle)
                if self._route_locator(channel_route.channels, channel_id) != locator:
                    raise StateError(f"Unknown application channel {channel_id!r}")
                try:
                    snapshot = shard.channels.get_by_handle(channel_handle)
                except KeyError:
                    raise StateError(f"Unknown application channel {channel_id!r}") from None
                if snapshot.channel_id != channel_id:
                    raise StateError(f"Unknown application channel {channel_id!r}")
                if not snapshot.is_open:
                    return snapshot
                canonical_time = self._require_window_time(
                    closed_at,
                    "channel closed_at",
                    allow_end_boundary=True,
                )
                if canonical_time < self._watermark:
                    raise StateError(
                        "Application channels cannot close before the current watermark"
                    )
                return self._close_locked(
                    shard,
                    channel_handle,
                    snapshot,
                    canonical_time,
                    reason,
                )

    def _close_locked(
        self,
        shard: _ApplicationChannelShard,
        handle: int,
        snapshot: ApplicationChannelSnapshot,
        closed_at: datetime,
        reason: str,
    ) -> ApplicationChannelSnapshot:
        if not snapshot.is_open:
            return snapshot
        if not reason.strip():
            raise StateError("Application channel closure requires a reason")
        if closed_at < snapshot.last_activity_at:
            raise StateError("Application channel cannot close before its last activity")
        if closed_at > self._effective_deadline(snapshot):
            raise StateError(
                "Application channel cannot close after its idle, hard, or transport deadline"
            )
        active_count = shard.operations.count("channel", snapshot.channel_id)
        if active_count:
            raise StateError(
                f"Application channel {snapshot.channel_id!r} cannot close with "
                f"{active_count} active operations"
            )
        updated = replace(snapshot, closed_at=closed_at, close_reason=reason.strip())
        shard.active_expiry.pop(handle, None)
        shard.operation_blocker_expiry.pop(handle, None)
        shard.channels.replace(handle, updated, known_prior=snapshot)
        shard.estimated_value_bytes += _snapshot_estimated_bytes(
            updated
        ) - _snapshot_estimated_bytes(snapshot)
        shard.mutation_version += 1
        retention_deadline = (closed_at + self._closed_grace).timestamp()
        shard.closed_expiry.set(handle, retention_deadline)
        shard.open_channels -= 1
        return updated

    @staticmethod
    def _purge_used_ids(shard: _ApplicationChannelShard, channel_handle: int) -> None:
        """Drop bounded used-ID markers through exact channel pages."""

        while True:
            removed, has_more = shard.used_operation_ids.purge_channel(
                channel_handle,
                limit=_USED_ID_PURGE_PAGE,
            )
            for used_key in removed:
                shard.used_id_deletions += 1
                shard.estimated_value_bytes -= _used_id_estimated_bytes(used_key)
            if not has_more:
                return

    def _evict_closed_page(
        self,
        shard: _ApplicationChannelShard,
        due: tuple[tuple[int, float], ...],
    ) -> int:
        """Delete one bounded tombstone page with route-before-owner locks."""

        candidates: list[tuple[int, int, str, str]] = []
        with shard.lock:
            for handle, _deadline in due:
                try:
                    generation, channel_id, transport_id, is_open, _active, _estimated = (
                        shard.channels.eviction_identity(handle)
                    )
                except KeyError:
                    continue
                if not is_open:
                    candidates.append((handle, generation, channel_id, transport_id))
        if not candidates:
            return 0
        route_entries: list[tuple[tuple[int, int], RLock]] = []
        channel_routes: dict[str, _RoutePartition] = {}
        transport_routes: dict[str, _RoutePartition] = {}
        for _handle, _generation, channel_id, transport_id in candidates:
            channel_route = self._route_partition("channel", channel_id, create=False)
            transport_route = self._route_partition("transport", transport_id, create=False)
            if channel_route is not None:
                channel_routes[channel_id] = channel_route
                route_entries.append(self._route_lock_entry(channel_route))
            if transport_route is not None:
                transport_routes[transport_id] = transport_route
                route_entries.append(self._route_lock_entry(transport_route))
        route_entries.append(self._owner_lock_entry(shard))
        evicted = 0
        with _acquire_stable_locks(route_entries):
            for handle, generation, channel_id, expected_transport_id in candidates:
                try:
                    (
                        retained_generation,
                        retained_channel_id,
                        transport_id,
                        is_open,
                        _active,
                        _estimated,
                    ) = shard.channels.eviction_identity(handle)
                except KeyError:
                    continue
                if (
                    is_open
                    or retained_generation != generation
                    or retained_channel_id != channel_id
                    or transport_id != expected_transport_id
                ):
                    continue
                locator = self._pack_channel_locator(shard.shard_id, handle)
                self._purge_used_ids(shard, handle)
                _transport_id, estimated_bytes = shard.channels.delete_primitive(
                    handle,
                    generation=generation,
                    channel_id=channel_id,
                )
                shard.estimated_value_bytes -= estimated_bytes
                shard.mutation_version += 1
                channel_route = channel_routes.get(channel_id)
                if channel_route is not None:
                    channel_digest = self._route_digest(channel_route.channels, channel_id)
                    if channel_route.channels.get_digest(channel_digest) == locator:
                        channel_route.channels.pop_digest(channel_digest)
                        channel_route.channel_deletions += 1
                transport_route = transport_routes.get(transport_id)
                if transport_route is not None:
                    transport_digest = self._route_digest(
                        transport_route.transports,
                        transport_id,
                    )
                    if transport_route.transports.get_digest(transport_digest) == locator:
                        transport_route.transports.pop_digest(transport_digest)
                        transport_route.transport_deletions += 1
                evicted += 1
        return evicted

    @staticmethod
    def _compact_shard_primary(shard: _ApplicationChannelShard, max_work: int) -> int:
        """Advance one shard's compact-store rotations within a fixed budget."""

        if max_work <= 0:
            return 0
        stores = (
            (shard.operations, "operation_deletions"),
            (shard.used_operation_ids, "used_id_deletions"),
        )
        work = 0
        visited = 0
        while visited < len(stores) and work < max_work:
            position = shard.compaction_cursor % len(stores)
            store, deletion_field = stores[position]
            visited += 1
            metrics = store.metrics()
            deletions = getattr(shard, deletion_field)
            if not deletions and not metrics.primary_compaction_pending:
                shard.compaction_cursor = (position + 1) % len(stores)
                continue
            inspected = store.compact_primary(
                max_slots=max_work - work,
                force=(
                    not metrics.primary_compaction_pending
                    and bool(deletions)
                    and metrics.live_entries == 0
                ),
            )
            work += inspected
            pending = store.metrics().primary_compaction_pending
            if not pending:
                setattr(shard, deletion_field, 0)
                shard.compaction_cursor = (position + 1) % len(stores)
            else:
                shard.compaction_cursor = position
                break
        return work

    def _compact_route_maps(self, max_work: int) -> int:
        """Compact exact routes incrementally without the global mutation gate."""

        if max_work <= 0:
            return 0
        with self._directory_lock:
            partitions = tuple(
                partition for partition in self._route_partitions if partition is not None
            )
        if not partitions:
            return 0
        work = 0
        visited = 0
        while visited < len(partitions) and work < max_work:
            position = self._route_compaction_cursor % len(partitions)
            partition = partitions[position]
            visited += 1
            with partition.lock:
                work += partition.compact_primary(max_work - work)
                pending = any(
                    metric.primary_compaction_pending for metric in partition.primary_metrics()
                )
            if pending:
                self._route_compaction_cursor = position
                break
            self._route_compaction_cursor = (position + 1) % len(partitions)
        return work

    def _reclaim_empty_route_partitions(self, max_partitions: int) -> int:
        """Retire a bounded page of empty lazy route partitions.

        The caller owns exclusive mutation admission.  Exact readers may still
        hold a reference to an empty retired partition, which is safe: they can
        only observe an absent route.  New mutations cannot retain or populate
        that retired object because route resolution now occurs after mutation
        admission.
        """

        if max_partitions <= 0:
            return 0
        reclaimed = 0
        inspected = 0
        while inspected < min(max_partitions, self._shard_count):
            partition_id = self._route_reclaim_cursor
            self._route_reclaim_cursor = (partition_id + 1) % self._shard_count
            inspected += 1
            with self._directory_lock:
                partition = self._route_partitions[partition_id]
            if partition is None:
                continue
            with partition.lock:
                if partition.channels or partition.transports or partition.operations:
                    continue
                # Empty-map compaction is O(1).  It records deletion-triggered
                # rotations before the partition object itself becomes
                # unreachable, preserving public cumulative observability.
                partition.compact_primary(1)
                metrics = partition.primary_metrics()
                with self._directory_lock:
                    if self._route_partitions[partition_id] is not partition:
                        continue
                    if partition.channels or partition.transports or partition.operations:
                        continue
                    self._route_partitions[partition_id] = None
                    self._retired_route_compaction_rotations += sum(
                        metric.primary_compaction_rotations for metric in metrics
                    )
                    self._retired_route_compaction_work += sum(
                        metric.primary_compaction_work for metric in metrics
                    )
                    self._retired_route_compaction_seconds += sum(
                        metric.primary_compaction_seconds for metric in metrics
                    )
                    reclaimed += 1
        return reclaimed

    def _compact_shard_maps(self, max_work: int) -> int:
        """Compact owner-shard primary maps without serializing disjoint owners."""

        if max_work <= 0:
            return 0
        with self._directory_lock:
            shards = tuple(sorted(self._shards.values(), key=lambda item: item.shard_id))
        if not shards:
            return 0
        work = 0
        visited = 0
        while visited < len(shards) and work < max_work:
            position = self._shard_compaction_cursor % len(shards)
            shard = shards[position]
            visited += 1
            with shard.lock:
                work += self._compact_shard_primary(shard, max_work - work)
                pending = any(
                    store.metrics().primary_compaction_pending
                    for store in (shard.operations, shard.used_operation_ids)
                )
            if pending:
                self._shard_compaction_cursor = position
                break
            self._shard_compaction_cursor = (position + 1) % len(shards)
        return work

    @staticmethod
    def _compact_shard_expiry(shard: _ApplicationChannelShard, max_work: int) -> int:
        """Advance one shard's packed expiry rebuilds within a fixed slot budget."""

        if max_work <= 0:
            return 0
        indexes = (
            shard.active_expiry,
            shard.closed_expiry,
            shard.operation_blocker_expiry,
        )
        work = 0
        visited = 0
        while visited < len(indexes) and work < max_work:
            position = shard.expiry_compaction_cursor % len(indexes)
            index = indexes[position]
            visited += 1
            work += index.compact(max_slots=max_work - work)
            if index.metrics().compaction_pending:
                shard.expiry_compaction_cursor = position
                break
            shard.expiry_compaction_cursor = (position + 1) % len(indexes)
        return work

    def _compact_expiry_indexes(self, max_work: int) -> int:
        """Compact packed expiry heaps without serializing disjoint owners."""

        if max_work <= 0:
            return 0
        with self._directory_lock:
            shards = tuple(sorted(self._shards.values(), key=lambda item: item.shard_id))
        if not shards:
            return 0
        work = 0
        visited = 0
        while visited < len(shards) and work < max_work:
            position = self._expiry_compaction_cursor % len(shards)
            shard = shards[position]
            visited += 1
            with shard.lock:
                work += self._compact_shard_expiry(shard, max_work - work)
                pending = any(
                    index.metrics().compaction_pending
                    for index in (
                        shard.active_expiry,
                        shard.closed_expiry,
                        shard.operation_blocker_expiry,
                    )
                )
            if pending:
                self._expiry_compaction_cursor = position
                break
            self._expiry_compaction_cursor = (position + 1) % len(shards)
        return work

    def watermark(self, at: datetime) -> ApplicationChannelCensus:
        """Close and evict due channels through bounded deterministic pages."""

        canonical_time = ensure_utc(at)
        with self._watermark_lane:
            with self._gate.watermark():
                if canonical_time < self._watermark:
                    raise StateError("Application channel watermarks must be monotonic")
                with self._prepared_lock:
                    if self._has_incomplete_prepared_release_locked():
                        raise StateError(
                            "Application watermark is fenced by an incomplete prepared release"
                        )
                    claimed_frontier = min(
                        (
                            *(
                                capability.linearization_time
                                for capability in self._prepared_capabilities.values()
                                if capability.reservation_id in self._claimed_reservations
                            ),
                            *(
                                capability.trusted_token.closed_at
                                for capability in self._prepared_close_capabilities.values()
                                if capability.reservation_id in self._claimed_reservations
                            ),
                        ),
                        default=None,
                    )
                if claimed_frontier is not None and canonical_time > claimed_frontier:
                    raise StateError(
                        "Application watermark cannot advance past a claimed admission at "
                        f"{claimed_frontier.isoformat()}"
                    )
                with self._directory_lock:
                    shards = tuple(sorted(self._shards.values(), key=lambda item: item.shard_id))
                cutoff = canonical_time.timestamp()
                blockers: list[str] = []
                for shard in shards:
                    with shard.lock:
                        while due := shard.operation_blocker_expiry.first_due_before(
                            cutoff,
                            inclusive=True,
                        ):
                            handle, _deadline = due
                            try:
                                (
                                    _generation,
                                    channel_id,
                                    _transport_id,
                                    is_open,
                                    active_operations,
                                    _estimated_bytes,
                                ) = shard.channels.eviction_identity(handle)
                            except KeyError:
                                shard.operation_blocker_expiry.pop(handle, None)
                                continue
                            if is_open and active_operations:
                                blockers.append(channel_id)
                                break
                            shard.operation_blocker_expiry.pop(handle, None)
                    if len(blockers) >= 3:
                        break
                if blockers:
                    preview = ", ".join(repr(channel_id) for channel_id in blockers)
                    suffix = " ..." if len(blockers) == 3 else ""
                    raise StateError(
                        f"Application watermark cannot close due channels with active "
                        f"operations: {preview}{suffix}"
                    )

                for shard in shards:
                    while True:
                        with shard.lock:
                            due = shard.active_expiry.expire_before_page(
                                cutoff,
                                inclusive=True,
                                limit=_EXPIRY_PAGE_SIZE,
                            )
                            if not due:
                                break
                            for handle, deadline in due:
                                try:
                                    (
                                        generation,
                                        channel_id,
                                        _transport_id,
                                        is_open,
                                        active_operations,
                                        _estimated_bytes,
                                    ) = shard.channels.eviction_identity(handle)
                                except KeyError:
                                    continue
                                if not is_open:
                                    continue
                                if active_operations:
                                    raise StateError(
                                        f"Application channel {channel_id!r} cannot close with "
                                        f"{active_operations} active operations"
                                    )
                                closed_at = datetime.fromtimestamp(deadline, tz=UTC)
                                self._close_handle_locked(
                                    shard,
                                    handle,
                                    generation=generation,
                                    channel_id=channel_id,
                                    closed_at=closed_at,
                                    reason="deadline",
                                )
                    while True:
                        with shard.lock:
                            due_closed = shard.closed_expiry.expire_before_page(
                                cutoff,
                                inclusive=True,
                                limit=_EXPIRY_PAGE_SIZE,
                            )
                        if not due_closed:
                            break
                        self._evict_closed_page(shard, due_closed)

                self._watermark = canonical_time

            # Rotations are bounded and partition-local.  They deliberately run
            # after the exclusive commit lane is released so unrelated owners
            # can continue mutating while a large retired map is migrated.
            self._compact_route_maps(_ROUTE_COMPACTION_WORK_PER_WATERMARK)
            self._compact_shard_maps(_PRIMARY_COMPACTION_WORK_PER_WATERMARK)
            self._compact_expiry_indexes(_EXPIRY_COMPACTION_WORK_PER_WATERMARK)
            # Reclamation is a separate, bounded admission fence after map
            # compaction.  It never scans entities or rebuilds a live map.
            with self._gate.watermark():
                self._reclaim_empty_route_partitions(_ROUTE_PARTITION_RECLAIM_PER_WATERMARK)
            return self.census()

    def census(self) -> ApplicationChannelCensus:
        """Return a bounded structural census across lazy fixed-count shards."""

        with self._prepared_lock:
            prepared_admission_tokens = len(self._prepared_reservations)
            prepared_admission_capabilities = len(self._prepared_capabilities)
            prepared_close_tokens = len(self._prepared_close_tokens)
            prepared_close_capabilities = len(self._prepared_close_capabilities)
            prepared_close_projection_authorities = {
                capability.reservation_id: capability.projection_authority
                for capability in self._prepared_close_capabilities.values()
            }
            for retained in (
                *self._recoverable_close_results.values(),
                *self._acknowledging_close_results.values(),
            ):
                authority = retained.projection_authority
                prepared_close_projection_authorities[authority.reservation_id] = authority
            prepared_close_projections = len(prepared_close_projection_authorities)
            prepared_commit_journals = len(self._prepared_commit_journals)
            prepared_close_commit_journals = len(self._prepared_close_commit_journals)
            releasing_admissions = len(self._releasing_reservations)
            acknowledging_admission_results = len(self._acknowledging_admission_results)
            acknowledging_close_results = len(self._acknowledging_close_results)
            prepared_admissions = prepared_admission_tokens + prepared_close_tokens
            claimed_admissions = len(self._claimed_reservations)
            reserved_channel_ids = len(self._prepared_channel_ids)
            reserved_transport_ids = len(self._prepared_transport_ids)
            reserved_operation_ids = len(self._prepared_operation_ids)
            recoverable_admission_slots = len(self._recoverable_admission_slots)
            recoverable_admission_results = len(
                set(self._recoverable_admission_results)
                | set(self._acknowledging_admission_results)
                | set(self._recoverable_close_results)
                | set(self._acknowledging_close_results)
            )
            recoverable_admission_receipts = len(
                {
                    id(retained.result.receipt)
                    for retained in (
                        *self._recoverable_admission_results.values(),
                        *self._acknowledging_admission_results.values(),
                    )
                    if retained.result.receipt is not None
                }
            )
            recoverable_close_results = len(
                set(self._recoverable_close_results) | set(self._acknowledging_close_results)
            )
            recoverable_close_receipts = len(
                {
                    id(retained.result.receipt)
                    for retained in (
                        *self._recoverable_close_results.values(),
                        *self._acknowledging_close_results.values(),
                    )
                }
            )
            estimated_prepared_bytes = (
                sys.getsizeof(self._prepared_reservations)
                + sys.getsizeof(self._prepared_capabilities)
                + sys.getsizeof(self._claimed_reservations)
                + sys.getsizeof(self._prepared_channel_ids)
                + sys.getsizeof(self._prepared_transport_ids)
                + sys.getsizeof(self._prepared_operation_ids)
                + sys.getsizeof(self._prepared_affinity_reservations)
                + sum(
                    sys.getsizeof(reservations)
                    for reservations in self._prepared_affinity_reservations.values()
                )
                + sys.getsizeof(self._prepared_close_tokens)
                + sys.getsizeof(self._prepared_close_capabilities)
                + sys.getsizeof(self._recoverable_admission_slots)
                + sys.getsizeof(self._recoverable_admission_results)
                + sys.getsizeof(self._recoverable_admission_receipts)
                + sys.getsizeof(self._recoverable_close_results)
                + sys.getsizeof(self._recoverable_close_receipts)
                + sys.getsizeof(self._prepared_commit_journals)
                + sys.getsizeof(self._prepared_close_commit_journals)
                + sys.getsizeof(self._releasing_reservations)
                + sys.getsizeof(self._acknowledging_admission_results)
                + sys.getsizeof(self._acknowledging_close_results)
                + sys.getsizeof(self._mutating_channel_ids)
                + sys.getsizeof(self._mutating_transport_ids)
                + sys.getsizeof(self._mutating_operation_ids)
                + sys.getsizeof(self._mutating_affinity_counts)
                + sum(
                    sys.getsizeof(reservation_id) + sys.getsizeof(token)
                    for reservation_id, token in self._prepared_reservations.items()
                )
                + sum(
                    sys.getsizeof(token_id) + sys.getsizeof(capability)
                    for token_id, capability in self._prepared_capabilities.items()
                )
                + sum(
                    sys.getsizeof(reservation_id) + sys.getsizeof(token)
                    for reservation_id, token in self._prepared_close_tokens.items()
                )
                + sum(
                    sys.getsizeof(token_id) + sys.getsizeof(capability)
                    for token_id, capability in self._prepared_close_capabilities.items()
                )
                + sum(
                    _prepared_close_projection_authority_estimated_bytes(authority)
                    for authority in prepared_close_projection_authorities.values()
                )
                + sum(
                    sys.getsizeof(reservation_id)
                    + sys.getsizeof(retained)
                    + sys.getsizeof(retained.token)
                    + sys.getsizeof(retained.result)
                    for reservation_id, retained in self._recoverable_admission_results.items()
                )
                + sum(
                    sys.getsizeof(reservation_id)
                    + sys.getsizeof(retained)
                    + sys.getsizeof(retained.token)
                    + sys.getsizeof(retained.result)
                    for reservation_id, retained in self._recoverable_close_results.items()
                )
                + sum(
                    sys.getsizeof(reservation_id) + sys.getsizeof(journal)
                    for reservation_id, journal in self._prepared_commit_journals.items()
                )
                + sum(
                    sys.getsizeof(reservation_id) + sys.getsizeof(journal)
                    for reservation_id, journal in self._prepared_close_commit_journals.items()
                )
                + sum(sys.getsizeof(value) for value in self._releasing_reservations)
                + sum(
                    sys.getsizeof(reservation_id)
                    + sys.getsizeof(retained)
                    + sys.getsizeof(retained.token)
                    + sys.getsizeof(retained.result)
                    for reservation_id, retained in self._acknowledging_admission_results.items()
                )
                + sum(
                    sys.getsizeof(reservation_id)
                    + sys.getsizeof(retained)
                    + sys.getsizeof(retained.token)
                    + sys.getsizeof(retained.result)
                    for reservation_id, retained in self._acknowledging_close_results.items()
                )
            )
        with self._directory_lock:
            shards = tuple(self._shards.values())
            route_partitions = tuple(
                partition for partition in self._route_partitions if partition is not None
            )
            retired_route_compaction = (
                self._retired_route_compaction_rotations,
                self._retired_route_compaction_work,
                self._retired_route_compaction_seconds,
            )
        lock_entries = [self._route_lock_entry(route) for route in route_partitions]
        lock_entries.extend(self._owner_lock_entry(shard) for shard in shards)
        with _acquire_stable_locks(lock_entries):
            active_metrics = [shard.active_expiry.metrics(estimate_bytes=True) for shard in shards]
            closed_metrics = [shard.closed_expiry.metrics(estimate_bytes=True) for shard in shards]
            blocker_metrics = [
                shard.operation_blocker_expiry.metrics(estimate_bytes=True) for shard in shards
            ]
            expiry_metrics = (*active_metrics, *closed_metrics, *blocker_metrics)
            route_store_metrics = [
                metric for route in route_partitions for metric in route.primary_metrics()
            ]
            shard_store_metrics = [
                store.metrics(estimate_bytes=True)
                for shard in shards
                for store in (shard.channels, shard.operations, shard.used_operation_ids)
            ]
            retained_channels = sum(len(shard.channels) for shard in shards)
            open_channels = sum(shard.open_channels for shard in shards)
            decoded_cache_entries = sum(shard.channels.decoded_cache_entries for shard in shards)
            decoded_cache_estimated_bytes = sum(
                shard.channels.decoded_cache_estimated_bytes for shard in shards
            )
            active_operations = sum(len(shard.operations) for shard in shards)
            used_operation_ids = sum(len(shard.used_operation_ids) for shard in shards)
            expiry_entries = sum(metric.backing_entries for metric in expiry_metrics)
            channel_route_entries = sum(len(route.channels) for route in route_partitions)
            transport_route_entries = sum(len(route.transports) for route in route_partitions)
            operation_route_entries = sum(len(route.operations) for route in route_partitions)
            route_entries = (
                channel_route_entries + transport_route_entries + operation_route_entries
            )
            route_map_bytes = sum(
                metric.primary_map_backing_bytes for metric in route_store_metrics
            )
            route_map_ideal_bytes = (
                len(route_partitions)
                * (2 * _EMPTY_PACKED_ROUTE_MAP_BYTES + _EMPTY_PRIMARY_MAP_BYTES)
                + route_entries * _ESTIMATED_ROUTE_HASH_ENTRY_BYTES
            )
            route_map_amplification = route_map_bytes / max(1, route_map_ideal_bytes)
            estimated_store_index_bytes = sum(
                metric.estimated_bytes for metric in shard_store_metrics
            )
            estimated_route_index_bytes = (
                sum(metric.estimated_bytes for metric in route_store_metrics)
                + operation_route_entries * _ESTIMATED_PACKED_ROUTE_VALUE_BYTES
            )
            estimated_expiry_index_bytes = sum(metric.estimated_bytes for metric in expiry_metrics)
            estimated_index_bytes = (
                estimated_store_index_bytes
                + estimated_route_index_bytes
                + estimated_expiry_index_bytes
            )
            estimated_bytes = (
                sys.getsizeof(self)
                + sys.getsizeof(self.__dict__)
                + sys.getsizeof(self._shards)
                + sys.getsizeof(self._route_partitions)
                + sum(
                    sys.getsizeof(shard)
                    + sys.getsizeof(shard._accounting)
                    + sys.getsizeof(shard._accounting.prepared_commit_ids)
                    + shard.estimated_value_bytes
                    for shard in shards
                )
                + decoded_cache_estimated_bytes
                + sum(sys.getsizeof(route) for route in route_partitions)
                + estimated_index_bytes
                + estimated_prepared_bytes
            )
            return ApplicationChannelCensus(
                retained_channels=retained_channels,
                open_channels=open_channels,
                retained_closed_channels=retained_channels - open_channels,
                active_operations=active_operations,
                used_operation_ids=used_operation_ids,
                prepared_admissions=prepared_admissions,
                claimed_admissions=claimed_admissions,
                reserved_channel_ids=reserved_channel_ids,
                reserved_transport_ids=reserved_transport_ids,
                reserved_operation_ids=reserved_operation_ids,
                shard_count=len(shards),
                max_shard_load=max((len(shard.channels) for shard in shards), default=0),
                decoded_cache_entries=decoded_cache_entries,
                decoded_cache_capacity=len(shards) * _DECODED_CACHE_PER_SHARD,
                decoded_cache_estimated_bytes=decoded_cache_estimated_bytes,
                estimated_prepared_bytes=estimated_prepared_bytes,
                estimated_bytes=estimated_bytes,
                estimated_index_bytes=estimated_index_bytes,
                estimated_store_index_bytes=estimated_store_index_bytes,
                estimated_route_index_bytes=estimated_route_index_bytes,
                estimated_expiry_index_bytes=estimated_expiry_index_bytes,
                expiry_entries=expiry_entries,
                stale_expiry_entries=sum(metric.stale_entries for metric in expiry_metrics),
                expiry_compaction_pending=sum(
                    metric.compaction_pending for metric in expiry_metrics
                ),
                expiry_compaction_work=sum(metric.compaction_work for metric in expiry_metrics),
                expiry_compaction_seconds=sum(
                    metric.compaction_seconds for metric in expiry_metrics
                ),
                maximum_affinity_bucket=max(
                    (shard.maximum_affinity_bucket for shard in shards),
                    default=0,
                ),
                lookup_candidates_inspected=sum(
                    shard.lookup_candidates_inspected for shard in shards
                ),
                high_water_mark=sum(shard.high_water_mark for shard in shards),
                route_entries=route_entries,
                route_map_bytes=route_map_bytes,
                route_map_amplification=route_map_amplification,
                route_compaction_pending=sum(
                    metric.primary_compaction_pending for metric in route_store_metrics
                ),
                route_compaction_rotations=sum(
                    metric.primary_compaction_rotations for metric in route_store_metrics
                )
                + retired_route_compaction[0],
                route_compaction_work=sum(
                    metric.primary_compaction_work for metric in route_store_metrics
                )
                + retired_route_compaction[1],
                route_compaction_seconds=sum(
                    metric.primary_compaction_seconds for metric in route_store_metrics
                )
                + retired_route_compaction[2],
                store_primary_map_bytes=sum(
                    metric.primary_map_backing_bytes for metric in shard_store_metrics
                ),
                store_primary_compaction_pending=sum(
                    metric.primary_compaction_pending for metric in shard_store_metrics
                ),
                store_primary_compaction_rotations=sum(
                    metric.primary_compaction_rotations for metric in shard_store_metrics
                ),
                store_primary_compaction_work=sum(
                    metric.primary_compaction_work for metric in shard_store_metrics
                ),
                store_primary_compaction_seconds=sum(
                    metric.primary_compaction_seconds for metric in shard_store_metrics
                ),
                watermark=self._watermark,
                recoverable_admission_slots=recoverable_admission_slots,
                recoverable_admission_results=recoverable_admission_results,
                recoverable_admission_capacity=_MAX_RECOVERABLE_ADMISSION_RESULTS,
                prepared_admission_tokens=prepared_admission_tokens,
                prepared_admission_capabilities=prepared_admission_capabilities,
                prepared_close_tokens=prepared_close_tokens,
                prepared_close_capabilities=prepared_close_capabilities,
                prepared_close_projections=prepared_close_projections,
                prepared_commit_journals=prepared_commit_journals,
                prepared_close_commit_journals=prepared_close_commit_journals,
                releasing_admissions=releasing_admissions,
                acknowledging_admission_results=acknowledging_admission_results,
                acknowledging_close_results=acknowledging_close_results,
                recoverable_admission_receipts=recoverable_admission_receipts,
                recoverable_close_results=recoverable_close_results,
                recoverable_close_receipts=recoverable_close_receipts,
            )

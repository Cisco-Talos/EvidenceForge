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
from dataclasses import dataclass, field, replace
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
class ApplicationChannelCloseResult:
    """Minimal authoritative outcome from a versioned channel close."""

    channel_id: str
    closed_at: datetime
    newly_closed: bool


@dataclass(frozen=True, slots=True)
class ApplicationChannelAdmissionToken:
    """Opaque reservation for one coupled channel mutation.

    Preparation reserves semantic IDs and affinity capacity without publishing
    a channel or operation.  The token remains caller-owned until it is
    cancelled or claimed by :meth:`ApplicationChannelRegistry.prepared_admission`.
    """

    kind: Literal[
        "open_completed",
        "open_completed_close",
        "completed_operation",
        "completed_operation_close",
    ]
    reservation: ApplicationOperationReservation
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
    _integrity_token: str = field(repr=False, default="")

    @property
    def linearization_time(self) -> datetime:
        """Return the canonical time that a claimed token fences."""

        candidates = [self.reservation.started_at]
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

    canonical = repr(
        (
            "application-channel-admission-v1",
            token.kind,
            token.reservation,
            token.identity,
            token.replacement_channel_id,
            token.replacement_closed_at,
            token.replacement_reason,
            token.channel_closed_at,
            token.channel_close_reason,
            token._registry_token,
            token._reservation_id,
            token._owner_shard_id,
            token._channel_handle,
            token._channel_generation,
            token._expected_snapshot,
            token._prepared_snapshot,
            token._reserved_channel_ids,
            token._reserved_transport_ids,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class _ApplicationChannelAdmissionCapability:
    """Registry-owned immutable locator and trusted admission preimage."""

    token_id: int
    reservation_id: int
    integrity_token: str
    trusted_token: ApplicationChannelAdmissionToken
    reserved_channel_ids: tuple[str, ...]
    reserved_transport_ids: tuple[str, ...]
    operation_id: str
    affinity_key: tuple[str, str] | None
    linearization_time: datetime


@dataclass(frozen=True, slots=True)
class ApplicationChannelAdmissionReceipt:
    """Authenticated proof of one committed prepared channel admission."""

    kind: Literal[
        "open_completed",
        "open_completed_close",
        "completed_operation",
        "completed_operation_close",
    ]
    publication_token: str
    channel_id: str
    operation_id: str
    snapshot: ApplicationChannelSnapshot
    close_token: ApplicationChannelCloseToken | None = None
    _registry_token: int = field(repr=False, default=0)
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

    canonical = repr(
        (
            "application-channel-admission-receipt-v1",
            receipt.kind,
            receipt.publication_token,
            receipt.channel_id,
            receipt.operation_id,
            receipt.snapshot,
            receipt.close_token,
            receipt._registry_token,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class ApplicationChannelAdmissionResult:
    """Frozen result of one prepared channel admission."""

    snapshot: ApplicationChannelSnapshot
    close_token: ApplicationChannelCloseToken | None = None
    receipt: ApplicationChannelAdmissionReceipt | None = None


class ApplicationChannelPreparedCommit:
    """No-fail channel commit capability valid inside its claim context."""

    __slots__ = ("_active", "_committed", "_registry", "_result", "_token")

    def __init__(
        self,
        registry: ApplicationChannelRegistry,
        token: ApplicationChannelAdmissionToken,
    ) -> None:
        self._registry = registry
        self._token = token
        self._active = True
        self._committed = False
        self._result: ApplicationChannelAdmissionResult | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact claim has committed."""

        return self._committed

    @property
    def result(self) -> ApplicationChannelAdmissionResult | None:
        """Return the committed result, if any."""

        return self._result

    def commit_no_fail(self) -> ApplicationChannelAdmissionResult:
        """Publish the already-validated mutation as the final transaction step."""

        if not self._active:
            raise StateError("application channel prepared commit is no longer active")
        if self._committed:
            raise StateError("application channel prepared admission was already committed")
        self._result = self._registry._commit_claimed_admission(self._token)
        self._committed = True
        return self._result

    def commit(self) -> ApplicationChannelAdmissionResult:
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
    open_channels: int = 0
    maximum_affinity_bucket: int = 0
    lookup_candidates_inspected: int = 0
    high_water_mark: int = 0
    mutation_version: int = 0
    estimated_value_bytes: int = 0
    operation_deletions: int = 0
    used_id_deletions: int = 0
    compaction_cursor: int = 0
    expiry_compaction_cursor: int = 0


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
        self._prepared_affinity_counts: dict[tuple[str, str], int] = {}
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

    def authenticates_admission_token(self, token: ApplicationChannelAdmissionToken) -> bool:
        """Return whether one intact token is currently active in this registry."""

        if not isinstance(token, ApplicationChannelAdmissionToken):
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

        if not isinstance(receipt, ApplicationChannelAdmissionReceipt):
            return False
        if receipt._registry_token != id(self):
            return False
        expected = _application_channel_admission_receipt_integrity_token(
            self._admission_secret,
            receipt,
        )
        return hmac.compare_digest(receipt._integrity_token, expected)

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
        if active is not token:
            raise StateError("application channel admission token is stale or already consumed")
        expected = _application_channel_admission_integrity_token(
            self._admission_secret,
            token,
        )
        if not hmac.compare_digest(token._integrity_token, capability.integrity_token) or not (
            hmac.compare_digest(expected, capability.integrity_token)
        ):
            raise StateError("application channel admission token integrity validation failed")
        return capability

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

        expected = _application_channel_admission_integrity_token(
            self._admission_secret,
            token,
        )
        if not hmac.compare_digest(token._integrity_token, expected):
            raise StateError("application channel admission token integrity validation failed")
        reservation_id = token._reservation_id
        self._reject_prepared_conflict_locked(
            channel_ids=token._reserved_channel_ids,
            transport_ids=token._reserved_transport_ids,
            operation_ids=(token.reservation.operation_id,),
        )
        affinity_key = (
            (token.identity.owner_id, token.identity.affinity_digest)
            if token.identity is not None
            else None
        )
        capability = _ApplicationChannelAdmissionCapability(
            token_id=id(token),
            reservation_id=reservation_id,
            integrity_token=expected,
            trusted_token=deepcopy(token),
            reserved_channel_ids=token._reserved_channel_ids,
            reserved_transport_ids=token._reserved_transport_ids,
            operation_id=token.reservation.operation_id,
            affinity_key=affinity_key,
            linearization_time=token.linearization_time,
        )
        self._prepared_reservations[reservation_id] = token
        self._prepared_capabilities[capability.token_id] = capability
        for channel_id in capability.reserved_channel_ids:
            self._prepared_channel_ids[channel_id] = reservation_id
        for transport_id in capability.reserved_transport_ids:
            self._prepared_transport_ids[transport_id] = reservation_id
        self._prepared_operation_ids[capability.operation_id] = reservation_id
        if affinity_key is not None:
            self._prepared_affinity_counts[affinity_key] = (
                self._prepared_affinity_counts.get(affinity_key, 0) + 1
            )

    def _release_prepared_capability_locked(
        self,
        capability: _ApplicationChannelAdmissionCapability,
    ) -> None:
        """Release reservations using only the registry-owned immutable locator."""

        active = self._prepared_reservations.pop(capability.reservation_id, None)
        retained = self._prepared_capabilities.pop(capability.token_id, None)
        if active is None or retained is not capability:
            return
        self._claimed_reservations.discard(capability.reservation_id)
        for channel_id in capability.reserved_channel_ids:
            if self._prepared_channel_ids.get(channel_id) == capability.reservation_id:
                self._prepared_channel_ids.pop(channel_id)
        for transport_id in capability.reserved_transport_ids:
            if self._prepared_transport_ids.get(transport_id) == capability.reservation_id:
                self._prepared_transport_ids.pop(transport_id)
        if self._prepared_operation_ids.get(capability.operation_id) == capability.reservation_id:
            self._prepared_operation_ids.pop(capability.operation_id)
        affinity_key = capability.affinity_key
        if affinity_key is not None:
            remaining = self._prepared_affinity_counts[affinity_key] - 1
            if remaining:
                self._prepared_affinity_counts[affinity_key] = remaining
            else:
                self._prepared_affinity_counts.pop(affinity_key)
        if not self._prepared_reservations:
            # CPython dictionaries retain peak-sized tables after individual
            # pops.  Emptying them explicitly keeps prepare/cancel churn from
            # becoming duration-retained state and restores exact census size.
            self._prepared_reservations.clear()
            self._prepared_capabilities.clear()
            self._claimed_reservations.clear()
            self._prepared_channel_ids.clear()
            self._prepared_transport_ids.clear()
            self._prepared_operation_ids.clear()
            self._prepared_affinity_counts.clear()

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
    ) -> ApplicationChannelAdmissionToken:
        """Reserve a fresh channel and first completed operation without publishing them."""

        return self._prepare_open_channel_with_completed_operation(
            identity,
            reservation,
            replacement_channel_id=replacement_channel_id,
            replacement_closed_at=replacement_closed_at,
            replacement_reason=replacement_reason,
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
    ) -> ApplicationChannelAdmissionToken:
        """Reserve a fresh channel and first completed operation without publishing them.

        An optional exact replacement is validated and reserved as part of the
        same token.  This lets HTTP retain the prior reusable transport when an
        external transport transaction aborts, while a successful commit closes
        the prior channel immediately before opening its replacement.
        """

        if reservation.channel_id != identity.channel_id:
            raise StateError("Initial application operation must target the channel being opened")
        if reservation.parent_operation_id:
            raise StateError("Initial completed application operation cannot have a parent")
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
                operation_ids=(reservation.operation_id,),
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
            operation_route = self._route_partition(
                "operation",
                reservation.operation_id,
                create=False,
            )
            if operation_route is not None:
                with operation_route.lock:
                    if reservation.operation_id in operation_route.operations:
                        raise StateError(
                            f"Duplicate active operation_id {reservation.operation_id!r}"
                        )

            owner_shard_id = self._owner_shard_id(identity.owner_id)
            shard = self._owner_shard(owner_shard_id, create=False)
            affinity_size = 0
            replacement_snapshot: ApplicationChannelSnapshot | None = None
            replacement_handle: int | None = None
            replacement_generation: int | None = None
            if shard is not None:
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

            affinity_key = (identity.owner_id, identity.affinity_digest)
            affinity_size += self._prepared_affinity_counts.get(affinity_key, 0)
            affinity_size += self._mutating_affinity_counts.get(affinity_key, 0)
            if affinity_size >= self._max_reusable_per_affinity:
                raise StateError(
                    f"Application affinity {identity.affinity_digest!r} already retains "
                    f"{affinity_size} reusable channels; limit is "
                    f"{self._max_reusable_per_affinity}"
                )
            completed = self._initial_completed_snapshot(identity, reservation)
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
                    "open_completed_close"
                    if canonical_channel_close is not None
                    else "open_completed"
                ),
                reservation=reservation,
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
    ) -> ApplicationChannelAdmissionToken:
        """Reserve one immediate operation without consuming channel budget."""

        return self._prepare_completed_operation(reservation)

    def prepare_completed_operation_and_close(
        self,
        reservation: ApplicationOperationReservation,
        *,
        closed_at: datetime,
        reason: str,
    ) -> ApplicationChannelAdmissionToken:
        """Reserve one immediate operation and its exact atomic channel close."""

        return self._prepare_completed_operation(
            reservation,
            closed_at=closed_at,
            close_reason=reason,
        )

    def _prepare_completed_operation(
        self,
        reservation: ApplicationOperationReservation,
        *,
        closed_at: datetime | None = None,
        close_reason: str = "",
    ) -> ApplicationChannelAdmissionToken:
        """Build one sealed immediate-operation token with an optional close."""

        reason = close_reason.strip()
        if (closed_at is None) != (not reason):
            raise ValueError("closed_at and close reason must be supplied together")

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

    def cancel_prepared_admission(self, token: ApplicationChannelAdmissionToken) -> bool:
        """Cancel one unclaimed channel reservation without publishing state."""

        with self._gate.mutation(), self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
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
            if not transaction.committed:
                self._cancel_claimed_admission(token)
            transaction._close()

    def _claim_prepared_admission(self, token: ApplicationChannelAdmissionToken) -> None:
        """Revalidate and claim one token in a short registry-only section."""

        with self._gate.mutation(), self._prepared_lock:
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

        if token.kind in {"open_completed", "open_completed_close"}:
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
            if trusted_token.kind in {"open_completed", "open_completed_close"}:
                result = self._commit_prepared_open_locked(trusted_token)
            else:
                result = self._commit_prepared_operation_locked(trusted_token)
            receipt = ApplicationChannelAdmissionReceipt(
                kind=trusted_token.kind,
                publication_token=capability.integrity_token,
                channel_id=result.snapshot.channel_id,
                operation_id=trusted_token.reservation.operation_id,
                snapshot=result.snapshot,
                close_token=result.close_token,
                _registry_token=id(self),
            )
            receipt = replace(
                receipt,
                _integrity_token=_application_channel_admission_receipt_integrity_token(
                    self._admission_secret,
                    receipt,
                ),
            )
            result = replace(result, receipt=receipt)
            self._release_prepared_capability_locked(capability)
            return result

    def _commit_prepared_open_locked(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> ApplicationChannelAdmissionResult:
        """Perform primitive replacement/open writes after claim validation."""

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
        operation_route = self._route_partition(
            "operation",
            token.reservation.operation_id,
            create=True,
        )
        assert shard is not None and channel_route is not None
        assert transport_route is not None and operation_route is not None
        lock_entries = [
            self._route_lock_entry(channel_route),
            self._route_lock_entry(transport_route),
            self._route_lock_entry(operation_route),
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
            used_id_key = (channel_handle, token.reservation.operation_id)
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
            shard.estimated_value_bytes += shard.channels.estimated_row_bytes(
                channel_handle
            ) + _used_id_estimated_bytes(used_id_key)
            shard.mutation_version += 1
            if token.kind == "open_completed_close":
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
                if token.kind == "open_completed_close"
                else ApplicationChannelCloseToken(
                    locator=locator,
                    generation=shard.channels.generation(channel_handle),
                )
            )
            return ApplicationChannelAdmissionResult(completed, close_token)

    def _commit_prepared_operation_locked(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> ApplicationChannelAdmissionResult:
        """Perform primitive immediate-operation writes after claim validation."""

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
            affinity_size = shard.channels.count_prepared_affinity(
                prepared_identity
            ) + self._prepared_affinity_counts.get(affinity_key, 0)
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
                affinity_size = shard.channels.count_prepared_affinity(
                    prepared_identity
                ) + self._prepared_affinity_counts.get(affinity_key, 0)
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
        return ApplicationChannelCloseResult(
            channel_id=channel_id,
            closed_at=authoritative_time,
            newly_closed=newly_closed,
        )

    def _close_channel_by_token_admitted(
        self,
        channel_id: str,
        *,
        token: ApplicationChannelCloseToken,
        closed_at: datetime,
        reason: str,
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
            )

    def close_channel_by_token(
        self,
        channel_id: str,
        *,
        token: ApplicationChannelCloseToken,
        closed_at: datetime,
        reason: str,
    ) -> ApplicationChannelCloseResult:
        """Close one exact channel without reconstructing its identity or plan."""

        with self._gate.mutation(), self._ordinary_mutation_admission(channel_ids=(channel_id,)):
            return self._close_channel_by_token_admitted(
                channel_id,
                token=token,
                closed_at=closed_at,
                reason=reason,
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
        if closed_at < snapshot.identity.opened_at:
            raise StateError("Application channel cannot close before it opens")
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
                    claimed_frontier = min(
                        (
                            capability.linearization_time
                            for capability in self._prepared_capabilities.values()
                            if capability.reservation_id in self._claimed_reservations
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
            prepared_admissions = len(self._prepared_reservations)
            claimed_admissions = len(self._claimed_reservations)
            reserved_channel_ids = len(self._prepared_channel_ids)
            reserved_transport_ids = len(self._prepared_transport_ids)
            reserved_operation_ids = len(self._prepared_operation_ids)
            estimated_prepared_bytes = (
                sys.getsizeof(self._prepared_reservations)
                + sys.getsizeof(self._prepared_capabilities)
                + sys.getsizeof(self._claimed_reservations)
                + sys.getsizeof(self._prepared_channel_ids)
                + sys.getsizeof(self._prepared_transport_ids)
                + sys.getsizeof(self._prepared_operation_ids)
                + sys.getsizeof(self._prepared_affinity_counts)
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
                + sum(sys.getsizeof(shard) + shard.estimated_value_bytes for shard in shards)
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
            )

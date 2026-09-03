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

"""Reusable indexes for duration-stable generation state.

The generator frequently needs both canonical primary-key lookup and queries by
entity attributes such as hostname, username, or network UID. These containers
keep those access paths synchronized at mutation time so hot queries do not scan
history whose size grows with scenario duration.
"""

from __future__ import annotations

import hashlib
import heapq
import math
import sys
from array import array
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Hashable, Iterator, MutableMapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import chain
from time import perf_counter
from typing import Generic, TypeVar, cast

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")
G = TypeVar("G", bound=Hashable)
OwnerT = TypeVar("OwnerT", bound=Hashable)

_MISSING = object()
_INLINE_TEMPORAL_GROUP = object()


@dataclass(frozen=True, slots=True)
class IndexMetrics:
    """Low-cost structural metrics for one duration-stable index."""

    live_entries: int
    backing_entries: int
    stale_entries: int = 0
    allocated_slots: int = 0
    secondary_buckets: int = 0
    max_bucket_size: int = 0
    high_water_mark: int = 0
    lookup_candidates_inspected: int = 0
    compaction_work: int = 0
    compaction_seconds: float = 0.0
    compaction_pending: bool = False
    estimated_bytes: int = 0
    primary_map_entries: int = 0
    primary_map_backing_bytes: int = 0
    primary_compaction_pending: bool = False
    primary_compaction_rotations: int = 0
    primary_compaction_work: int = 0
    primary_compaction_seconds: float = 0.0
    protected_entries: int = 0
    protected_high_water_mark: int = 0

    @property
    def backing_amplification(self) -> float:
        """Return physical backing entries per live entry."""
        if self.live_entries == 0:
            return 0.0 if self.backing_entries == 0 else math.inf
        return self.backing_entries / self.live_entries

    @property
    def primary_map_amplification(self) -> float:
        """Return physical primary-map entries per live entry."""

        if self.live_entries == 0:
            return 0.0 if self.primary_map_entries == 0 else math.inf
        return self.primary_map_entries / self.live_entries


class PackedUniqueDigestMap:
    """Open-addressed exact route map with packed 64-bit keys and 32-bit locators.

    Semantic string callers receive a stable personalized BLAKE2 digest. Callers
    that already own a stable 64-bit semantic digest may use the ``*_digest``
    methods and must still verify canonical identity after resolving a locator.
    """

    _EMPTY = 2**64 - 1
    _EMPTY_LOCATOR = 2**32 - 1

    __slots__ = ("_count", "_high_water_mark", "_keys", "_namespace", "_values")

    def __init__(self, namespace: bytes) -> None:
        """Create an empty map with one BLAKE2 personalization namespace."""

        if not namespace or len(namespace) > 16:
            raise ValueError("Packed digest-map namespace must contain 1 to 16 bytes")
        self._namespace = namespace
        self._keys = array("Q", [self._EMPTY]) * 8
        self._values = array("I", [0]) * 8
        self._count = 0
        self._high_water_mark = 0

    def __len__(self) -> int:
        return self._count

    def __contains__(self, semantic_key: object) -> bool:
        return isinstance(semantic_key, str) and self._find_slot(self.digest(semantic_key))[1]

    def digest(self, semantic_key: str) -> int:
        """Return the stable non-sentinel digest for one semantic string."""

        digest = hashlib.blake2b(
            semantic_key.encode("utf-8"),
            digest_size=8,
            person=self._namespace,
        ).digest()
        return int.from_bytes(digest, "big") & (self._EMPTY - 1)

    @classmethod
    def _normalize_digest(cls, digest: int) -> int:
        if digest < 0 or digest > cls._EMPTY:
            raise ValueError("Packed route digest must fit in an unsigned 64-bit integer")
        return cls._EMPTY - 1 if digest == cls._EMPTY else digest

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

    def __setitem__(self, semantic_key: str, locator: int) -> None:
        self.set_digest(self.digest(semantic_key), locator)

    def set_digest(self, digest: int, locator: int) -> None:
        """Set one prehashed semantic digest to a compact locator."""

        if locator < 0 or locator >= self._EMPTY_LOCATOR:
            raise OverflowError("Packed route locator exceeds 32-bit capacity")
        canonical_digest = self._normalize_digest(digest)
        position, found = self._find_slot(canonical_digest)
        if not found and (self._count + 1) * 4 > len(self._keys) * 3:
            self._resize(len(self._keys) * 2)
            position, found = self._find_slot(canonical_digest)
        if not found:
            self._keys[position] = canonical_digest
            self._count += 1
            self._high_water_mark = max(self._high_water_mark, self._count)
        self._values[position] = locator

    def get(self, semantic_key: str, default: int | None = None) -> int | None:
        """Return the locator for one semantic string, or ``default``."""

        return self.get_digest(self.digest(semantic_key), default)

    def get_digest(self, digest: int, default: int | None = None) -> int | None:
        """Return the locator for one prehashed digest, or ``default``."""

        position, found = self._find_slot(self._normalize_digest(digest))
        return self._values[position] if found else default

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

    def pop(self, semantic_key: str, default: int | None = None) -> int | None:
        """Remove and return one semantic-string locator, or ``default``."""

        return self.pop_digest(self.digest(semantic_key), default)

    def pop_digest(self, digest: int, default: int | None = None) -> int | None:
        """Remove and return one prehashed locator, or ``default``."""

        position, found = self._find_slot(self._normalize_digest(digest))
        if not found:
            return default
        value = self._values[position]
        self._delete_position(position)
        self._count -= 1
        return value

    def compact_primary(self, *, max_entries: int = 4_096, force: bool = False) -> int:
        """Drop empty retained capacity in O(1); live tables need no rebuild."""

        if max_entries < 0:
            raise ValueError("Packed route compaction budget cannot be negative")
        if force and self._count == 0 and len(self._keys) > 8:
            self._keys = array("Q", [self._EMPTY]) * 8
            self._values = array("I", [0]) * 8
        return 0

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return exact packed route capacity without scanning semantic values."""

        backing_bytes = sys.getsizeof(self._keys) + sys.getsizeof(self._values)
        return IndexMetrics(
            live_entries=self._count,
            backing_entries=self._count,
            high_water_mark=self._high_water_mark,
            estimated_bytes=(sys.getsizeof(self) + backing_bytes if estimate_bytes else 0),
            primary_map_entries=self._count,
            primary_map_backing_bytes=backing_bytes,
        )


@dataclass(slots=True)
class _CompactHandleBucket:
    """One equality bucket backed by shared compact link arrays."""

    bucket_id: int
    head: int = -1
    tail: int = -1
    size: int = 0


class _CompactSecondaryIndex:
    """O(1) equality membership with resumable insertion-order pages."""

    def __init__(self) -> None:
        self.buckets: dict[Hashable, int | _CompactHandleBucket] = {}
        self.memberships = array("I")
        self.previous = array("q")
        self.next = array("q")
        self._free_bucket_ids: list[int] = []
        self._next_bucket_id = 0
        self._bucket_size_counts: dict[int, int] = {}
        self.max_bucket_size = 0

    def _adjust_bucket_size(self, old_size: int, new_size: int) -> None:
        if old_size:
            old_count = self._bucket_size_counts[old_size] - 1
            if old_count:
                self._bucket_size_counts[old_size] = old_count
            else:
                del self._bucket_size_counts[old_size]
        if new_size:
            self._bucket_size_counts[new_size] = self._bucket_size_counts.get(new_size, 0) + 1
        self.max_bucket_size = max(self.max_bucket_size, new_size)
        if self.max_bucket_size not in self._bucket_size_counts:
            self.max_bucket_size = max(self._bucket_size_counts, default=0)

    def _ensure_handle(self, handle: int) -> None:
        missing = handle + 1 - len(self.memberships)
        if missing <= 0:
            return
        self.memberships.extend(array("I", [0]) * missing)
        self.previous.extend(array("q", [-1]) * missing)
        self.next.extend(array("q", [-1]) * missing)

    def _new_bucket(self) -> _CompactHandleBucket:
        if self._free_bucket_ids:
            bucket_id = self._free_bucket_ids.pop()
        else:
            bucket_id = self._next_bucket_id
            self._next_bucket_id += 1
        if bucket_id >= (1 << 32) - 1:
            raise OverflowError("CompactIndexedStore exhausted secondary bucket IDs")
        return _CompactHandleBucket(bucket_id=bucket_id)

    def _append(self, bucket: _CompactHandleBucket, handle: int) -> None:
        self._ensure_handle(handle)
        prior_tail = bucket.tail
        self.memberships[handle] = bucket.bucket_id + 1
        self.previous[handle] = prior_tail
        self.next[handle] = -1
        if prior_tail >= 0:
            self.next[prior_tail] = handle
        else:
            bucket.head = handle
        bucket.tail = handle
        bucket.size += 1

    def add(self, indexed_value: Hashable, handle: int) -> None:
        bucket = self.buckets.get(indexed_value)
        if bucket is None:
            self.buckets[indexed_value] = handle
            self._adjust_bucket_size(0, 1)
            return
        if isinstance(bucket, int):
            promoted = self._new_bucket()
            self.buckets[indexed_value] = promoted
            self._append(promoted, bucket)
            self._append(promoted, handle)
            self._adjust_bucket_size(1, 2)
            return
        prior_size = bucket.size
        self._append(bucket, handle)
        self._adjust_bucket_size(prior_size, bucket.size)

    def remove(self, indexed_value: Hashable, handle: int) -> None:
        bucket = self.buckets.get(indexed_value)
        if isinstance(bucket, int):
            if bucket == handle:
                del self.buckets[indexed_value]
                self._adjust_bucket_size(1, 0)
            return
        if (
            bucket is None
            or handle >= len(self.memberships)
            or self.memberships[handle] != bucket.bucket_id + 1
        ):
            return
        prior_size = bucket.size
        previous_handle = self.previous[handle]
        next_handle = self.next[handle]
        if previous_handle >= 0:
            self.next[previous_handle] = next_handle
        else:
            bucket.head = next_handle
        if next_handle >= 0:
            self.previous[next_handle] = previous_handle
        else:
            bucket.tail = previous_handle
        self.memberships[handle] = 0
        self.previous[handle] = -1
        self.next[handle] = -1
        bucket.size -= 1
        if bucket.size == 0:
            del self.buckets[indexed_value]
            self._free_bucket_ids.append(bucket.bucket_id)
        elif bucket.size == 1:
            remaining = bucket.head
            self.memberships[remaining] = 0
            self.previous[remaining] = -1
            self.next[remaining] = -1
            self.buckets[indexed_value] = remaining
            self._free_bucket_ids.append(bucket.bucket_id)
        self._adjust_bucket_size(prior_size, bucket.size)

    def iter_handles(self, indexed_value: Hashable) -> Iterator[int]:
        bucket = self.buckets.get(indexed_value)
        if isinstance(bucket, int):
            yield bucket
            return
        handle = -1 if bucket is None else bucket.head
        while handle >= 0:
            yield handle
            handle = self.next[handle]

    def page(
        self,
        indexed_value: Hashable,
        *,
        after_handle: int | None,
        limit: int,
    ) -> tuple[tuple[int, ...], int | None]:
        bucket = self.buckets.get(indexed_value)
        if bucket is None:
            return (), None
        if isinstance(bucket, int):
            if after_handle is None:
                return (bucket,), None
            if after_handle != bucket:
                raise KeyError(f"stale compact index page cursor {after_handle}")
            return (), None
        if after_handle is None:
            handle = bucket.head
        else:
            if (
                after_handle < 0
                or after_handle >= len(self.memberships)
                or self.memberships[after_handle] != bucket.bucket_id + 1
            ):
                raise KeyError(f"stale compact index page cursor {after_handle}")
            handle = self.next[after_handle]
        page: list[int] = []
        while handle >= 0 and len(page) < limit:
            page.append(handle)
            handle = self.next[handle]
        cursor = page[-1] if page and handle >= 0 else None
        return tuple(page), cursor

    def count(self, indexed_value: Hashable) -> int:
        bucket = self.buckets.get(indexed_value)
        if bucket is None:
            return 0
        return 1 if isinstance(bucket, int) else bucket.size

    def estimated_bytes(self) -> int:
        """Return a structural size estimate during an explicit census."""
        return sum(
            sys.getsizeof(value)
            for value in (
                self,
                self.buckets,
                self.memberships,
                self.previous,
                self.next,
                self._free_bucket_ids,
                self._bucket_size_counts,
            )
        ) + sum(
            sys.getsizeof(bucket)
            for bucket in self.buckets.values()
            if isinstance(bucket, _CompactHandleBucket)
        )


class CompactEqualityIndex(_CompactSecondaryIndex):
    """Public handle-only equality index for packed registry value columns."""


class CompactIndexedStore(MutableMapping[K, V], Generic[K, V]):
    """Primary storage with compact integer-handle equality indexes.

    Values are expected to be immutable while stored. Replacing a value updates
    every secondary index atomically; mutation-plus-refresh is intentionally not
    supported. Secondary indexes retain integer handles instead of duplicating
    potentially large semantic keys in every bucket.
    """

    _PRIMARY_COMPACT_MIN_PEAK = 4_096
    _PRIMARY_COMPACT_RATIO = 2

    def __init__(
        self,
        *,
        track_lookup_candidates: bool = False,
        **indexers: Callable[[V], Hashable],
    ) -> None:
        """Create an empty lazily indexed store."""
        self._handles: dict[K, int] = {}
        self._retired_handles: dict[K, int] | None = None
        self._primary_compaction_cursor = 0
        self._primary_peak_entries = 0
        self._primary_compaction_rotations = 0
        self._primary_compaction_work = 0
        self._primary_compaction_seconds = 0.0
        self._live_count = 0
        self._slot_keys: list[K | object] = []
        self._slot_values: list[V | object] = []
        self._free_handles: list[int] = []
        self._indexers = indexers
        self._indexes: dict[str, _CompactSecondaryIndex] = {}
        self._track_lookup_candidates = track_lookup_candidates
        self._lookup_candidates_inspected = 0
        self._high_water_mark = 0

    def __getitem__(self, key: K) -> V:
        try:
            handle = self._handles[key]
        except KeyError:
            retired = self._retired_handles
            if retired is None:
                raise
            handle = retired[key]
        value = self._slot_values[handle]
        if value is _MISSING:  # pragma: no cover - protected by synchronized maps
            raise KeyError(key)
        return cast(V, value)

    def __setitem__(self, key: K, value: V) -> None:
        indexed_values = self._extract_indexed_values(value)
        handle = self._handles.get(key)
        if handle is None and self._retired_handles is not None:
            handle = self._retired_handles.pop(key, None)
            if handle is not None:
                self._handles[key] = handle
        if handle is not None:
            current = self._slot_values[handle]
            if current is not _MISSING:
                current_indexed_values = self._extract_indexed_values(cast(V, current))
                self._remove_indexes(handle, current_indexed_values)
            self._slot_values[handle] = value
            self._add_indexes(handle, indexed_values)
            return

        if self._free_handles:
            handle = self._free_handles.pop()
            self._slot_keys[handle] = key
            self._slot_values[handle] = value
        else:
            handle = len(self._slot_values)
            self._slot_keys.append(key)
            self._slot_values.append(value)
        self._handles[key] = handle
        self._live_count += 1
        self._primary_peak_entries = max(self._primary_peak_entries, len(self._handles))
        self._add_indexes(handle, indexed_values)
        self._high_water_mark = max(self._high_water_mark, self._live_count)

    def __delitem__(self, key: K) -> None:
        try:
            handle = self._handles.pop(key)
        except KeyError:
            retired = self._retired_handles
            if retired is None:
                raise
            handle = retired.pop(key)
        value = self._slot_values[handle]
        indexed_values: dict[str, Hashable] = {}
        if value is not _MISSING:
            indexed_values = self._extract_indexed_values(cast(V, value))
        self._remove_indexes(handle, indexed_values)
        self._slot_keys[handle] = _MISSING
        self._slot_values[handle] = _MISSING
        self._free_handles.append(handle)
        self._live_count -= 1

    def __iter__(self) -> Iterator[K]:
        retired = self._retired_handles
        if retired is None:
            return iter(self._handles)
        return chain(self._handles, retired)

    def __len__(self) -> int:
        return self._live_count

    def _index(self, index_name: str) -> _CompactSecondaryIndex | None:
        if index_name not in self._indexers:
            raise KeyError(f"unknown compact index {index_name!r}")
        return self._indexes.get(index_name)

    def _extract_indexed_values(self, value: V) -> dict[str, Hashable]:
        indexed_values: dict[str, Hashable] = {}
        for name, extractor in self._indexers.items():
            indexed_value = extractor(value)
            hash(indexed_value)
            indexed_values[name] = indexed_value
        return indexed_values

    def _add_indexes(self, handle: int, indexed_values: dict[str, Hashable]) -> None:
        for name, indexed_value in indexed_values.items():
            index = self._indexes.get(name)
            if index is None:
                index = _CompactSecondaryIndex()
                self._indexes[name] = index
            index.add(indexed_value, handle)

    def _remove_indexes(self, handle: int, indexed_values: dict[str, Hashable]) -> None:
        for name, indexed_value in indexed_values.items():
            index = self._indexes.get(name)
            if index is None:
                continue
            index.remove(indexed_value, handle)
            if not index.buckets:
                del self._indexes[name]

    def handle_for(self, key: K) -> int:
        """Return the compact live handle for a semantic key."""

        try:
            return self._handles[key]
        except KeyError:
            retired = self._retired_handles
            if retired is None:
                raise
            return retired[key]

    def compact_primary(self, *, max_slots: int = 4_096, force: bool = False) -> int:
        """Incrementally rotate an over-allocated semantic-key map.

        The store is intentionally unsynchronized; callers must hold the same
        lock they use for mutation. Starting a rotation is constant time.
        Subsequent calls inspect at most ``max_slots`` compact backing slots,
        while exact lookup remains available through active and retired maps.
        """

        if max_slots < 0:
            raise ValueError("CompactIndexedStore max_slots must be non-negative")
        started = perf_counter()
        retired = self._retired_handles
        if retired is None:
            amplified = (
                self._primary_peak_entries >= self._PRIMARY_COMPACT_MIN_PEAK
                and self._primary_peak_entries
                > max(
                    self._live_count * self._PRIMARY_COMPACT_RATIO,
                    self._live_count + self._PRIMARY_COMPACT_MIN_PEAK,
                )
            )
            if not force and not amplified:
                self._primary_compaction_seconds += perf_counter() - started
                return 0
            self._retired_handles = self._handles
            self._handles = {}
            self._primary_compaction_cursor = 0
            self._primary_peak_entries = 0
            retired = self._retired_handles

        if not retired:
            self._retired_handles = None
            self._primary_compaction_cursor = 0
            self._primary_compaction_rotations += 1
            self._primary_peak_entries = len(self._handles)
            self._primary_compaction_seconds += perf_counter() - started
            return 0

        stop = min(len(self._slot_keys), self._primary_compaction_cursor + max_slots)
        inspected = stop - self._primary_compaction_cursor
        for handle in range(self._primary_compaction_cursor, stop):
            key = self._slot_keys[handle]
            if key is _MISSING:
                continue
            semantic_key = cast(K, key)
            if retired.get(semantic_key) != handle:
                continue
            self._handles[semantic_key] = handle
            retired.pop(semantic_key)
        self._primary_compaction_cursor = stop
        self._primary_peak_entries = max(self._primary_peak_entries, len(self._handles))
        self._primary_compaction_work += inspected
        if stop == len(self._slot_keys):
            if retired:  # pragma: no cover - synchronized slot/map invariant
                raise AssertionError("CompactIndexedStore primary rotation left live keys behind")
            self._retired_handles = None
            self._primary_compaction_cursor = 0
            self._primary_compaction_rotations += 1
            self._primary_peak_entries = len(self._handles)
        self._primary_compaction_seconds += perf_counter() - started
        return inspected

    def get_by_handle(self, handle: int) -> V:
        """Return a live value by its compact handle."""
        if handle < 0 or handle >= len(self._slot_values):
            raise KeyError(handle)
        value = self._slot_values[handle]
        if value is _MISSING:
            raise KeyError(handle)
        return cast(V, value)

    def iter_values_by_handle(self) -> Iterator[V]:
        """Yield live values in stable compact-handle order."""

        for value in self._slot_values:
            if value is not _MISSING:
                yield cast(V, value)

    def key_by_handle(self, handle: int) -> K:
        """Return a live semantic key by its compact handle."""
        if handle < 0 or handle >= len(self._slot_keys):
            raise KeyError(handle)
        key = self._slot_keys[handle]
        if key is _MISSING:
            raise KeyError(handle)
        return cast(K, key)

    def find_iter(self, index_name: str, indexed_value: Hashable) -> Iterator[V]:
        """Yield matching values without materializing the full result set."""
        index = self._index(index_name)
        if index is None:
            return
        handles = index.iter_handles(indexed_value)
        if self._track_lookup_candidates:
            yield from self._tracked_value_iter(handles)
            return
        for handle in handles:
            value = self._slot_values[handle]
            if value is not _MISSING:
                yield cast(V, value)

    def _tracked_value_iter(self, handles: Iterator[int]) -> Iterator[V]:
        for handle in handles:
            self._lookup_candidates_inspected += 1
            value = self._slot_values[handle]
            if value is not _MISSING:
                yield cast(V, value)

    def find_key_iter(self, index_name: str, indexed_value: Hashable) -> Iterator[K]:
        """Yield matching semantic keys without copying the index bucket."""
        index = self._index(index_name)
        if index is None:
            return
        for handle in index.iter_handles(indexed_value):
            if self._track_lookup_candidates:
                self._lookup_candidates_inspected += 1
            key = self._slot_keys[handle]
            if key is not _MISSING:
                yield cast(K, key)

    def find_one(self, index_name: str, indexed_value: Hashable) -> V | None:
        """Return the first matching value, if any."""
        return next(self.find_iter(index_name, indexed_value), None)

    def find_handle_page(
        self,
        index_name: str,
        indexed_value: Hashable,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[int, ...], int | None]:
        """Return one frozen equality-bucket page and a resumable cursor.

        Page order is deterministic secondary-index insertion order. A cursor
        is valid only while its handle remains in the same bucket; mutation of
        that cursor raises ``KeyError`` instead of silently skipping records.
        """
        if limit <= 0:
            raise ValueError("CompactIndexedStore page limit must be positive")
        index = self._index(index_name)
        if index is None:
            return (), None
        return index.page(indexed_value, after_handle=after_handle, limit=limit)

    def count(self, index_name: str, indexed_value: Hashable) -> int:
        """Return a secondary bucket's live cardinality in constant time."""
        index = self._index(index_name)
        return 0 if index is None else index.count(indexed_value)

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return structural metrics without traversing stored values."""
        estimated_bytes = 0
        if estimate_bytes:
            estimated_bytes = sum(
                sys.getsizeof(value)
                for value in (
                    self,
                    self._handles,
                    self._slot_keys,
                    self._slot_values,
                    self._free_handles,
                    self._indexers,
                    self._indexes,
                )
            )
            if self._retired_handles is not None:
                estimated_bytes += sys.getsizeof(self._retired_handles)
            estimated_bytes += sum(index.estimated_bytes() for index in self._indexes.values())
        primary_map_entries = len(self._handles) + (
            0 if self._retired_handles is None else len(self._retired_handles)
        )
        primary_map_backing_bytes = sys.getsizeof(self._handles) + (
            0 if self._retired_handles is None else sys.getsizeof(self._retired_handles)
        )
        return IndexMetrics(
            live_entries=len(self),
            backing_entries=len(self._slot_values),
            stale_entries=len(self._free_handles),
            allocated_slots=len(self._slot_values),
            secondary_buckets=sum(len(index.buckets) for index in self._indexes.values()),
            max_bucket_size=max(
                (index.max_bucket_size for index in self._indexes.values()), default=0
            ),
            high_water_mark=self._high_water_mark,
            lookup_candidates_inspected=self._lookup_candidates_inspected,
            estimated_bytes=estimated_bytes,
            primary_map_entries=primary_map_entries,
            primary_map_backing_bytes=primary_map_backing_bytes,
            primary_compaction_pending=self._retired_handles is not None,
            primary_compaction_rotations=self._primary_compaction_rotations,
            primary_compaction_work=self._primary_compaction_work,
            primary_compaction_seconds=self._primary_compaction_seconds,
        )


class CompactHandleStore(Generic[V]):
    """Dense handle-owned values with lazy equality indexes and no key map.

    An external exact route may already own semantic-key-to-handle resolution.
    This store avoids retaining that semantic key a second time while preserving
    compact secondary buckets, bounded pages, handle reuse, and O(1) mutation.
    """

    def __init__(
        self,
        *,
        track_lookup_candidates: bool = False,
        **indexers: Callable[[V], Hashable | None],
    ) -> None:
        self._slot_values: list[V | object] = []
        self._free_handles: list[int] = []
        self._indexers = indexers
        self._indexes: dict[str, _CompactSecondaryIndex] = {}
        self._track_lookup_candidates = track_lookup_candidates
        self._lookup_candidates_inspected = 0
        self._live_count = 0
        self._high_water_mark = 0

    def __len__(self) -> int:
        return self._live_count

    def _index(self, index_name: str) -> _CompactSecondaryIndex | None:
        if index_name not in self._indexers:
            raise KeyError(f"unknown compact index {index_name!r}")
        return self._indexes.get(index_name)

    def _extract_indexed_values(self, value: V) -> dict[str, Hashable]:
        indexed_values: dict[str, Hashable] = {}
        for name, extractor in self._indexers.items():
            indexed_value = extractor(value)
            if indexed_value is None:
                continue
            hash(indexed_value)
            indexed_values[name] = indexed_value
        return indexed_values

    def _add_indexes(self, handle: int, indexed_values: dict[str, Hashable]) -> None:
        for name, indexed_value in indexed_values.items():
            index = self._indexes.get(name)
            if index is None:
                index = _CompactSecondaryIndex()
                self._indexes[name] = index
            index.add(indexed_value, handle)

    def _remove_indexes(self, handle: int, indexed_values: dict[str, Hashable]) -> None:
        for name, indexed_value in indexed_values.items():
            index = self._indexes.get(name)
            if index is None:
                continue
            index.remove(indexed_value, handle)
            if not index.buckets:
                del self._indexes[name]

    def insert(self, value: V) -> int:
        """Insert one value and return its compact reusable handle."""

        indexed_values = self._extract_indexed_values(value)
        if self._free_handles:
            handle = self._free_handles.pop()
            self._slot_values[handle] = value
        else:
            handle = len(self._slot_values)
            self._slot_values.append(value)
        self._add_indexes(handle, indexed_values)
        self._live_count += 1
        self._high_water_mark = max(self._high_water_mark, self._live_count)
        return handle

    def replace(self, handle: int, value: V) -> V:
        """Replace a live handle atomically and return its prior value."""

        indexed_values = self._extract_indexed_values(value)
        prior = self.get_by_handle(handle)
        prior_indexed_values = self._extract_indexed_values(prior)
        self._remove_indexes(handle, prior_indexed_values)
        self._slot_values[handle] = value
        self._add_indexes(handle, indexed_values)
        return prior

    def delete(self, handle: int) -> V:
        """Delete one live handle and return its prior value."""

        prior = self.get_by_handle(handle)
        self._remove_indexes(handle, self._extract_indexed_values(prior))
        self._slot_values[handle] = _MISSING
        self._free_handles.append(handle)
        self._live_count -= 1
        return prior

    def get_by_handle(self, handle: int) -> V:
        """Return one live handle value or raise ``KeyError``."""

        if handle < 0 or handle >= len(self._slot_values):
            raise KeyError(handle)
        value = self._slot_values[handle]
        if value is _MISSING:
            raise KeyError(handle)
        return cast(V, value)

    def find_iter(self, index_name: str, indexed_value: Hashable) -> Iterator[V]:
        """Yield exact equality matches without materializing a collection."""

        index = self._index(index_name)
        if index is None:
            return
        for handle in index.iter_handles(indexed_value):
            if self._track_lookup_candidates:
                self._lookup_candidates_inspected += 1
            value = self._slot_values[handle]
            if value is not _MISSING:
                yield cast(V, value)

    def find_handle_page(
        self,
        index_name: str,
        indexed_value: Hashable,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[int, ...], int | None]:
        """Return one bounded equality page and its resumable handle cursor."""

        if limit <= 0:
            raise ValueError("CompactHandleStore page limit must be positive")
        index = self._index(index_name)
        if index is None:
            return (), None
        return index.page(indexed_value, after_handle=after_handle, limit=limit)

    def count(self, index_name: str, indexed_value: Hashable) -> int:
        """Return one equality bucket's live cardinality in constant time."""

        index = self._index(index_name)
        return 0 if index is None else index.count(indexed_value)

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return handle/secondary structural metrics without reading values."""

        estimated_bytes = 0
        if estimate_bytes:
            estimated_bytes = sum(
                sys.getsizeof(value)
                for value in (
                    self,
                    self._slot_values,
                    self._free_handles,
                    self._indexers,
                    self._indexes,
                )
            ) + sum(index.estimated_bytes() for index in self._indexes.values())
        return IndexMetrics(
            live_entries=self._live_count,
            backing_entries=len(self._slot_values),
            stale_entries=len(self._free_handles),
            allocated_slots=len(self._slot_values),
            secondary_buckets=sum(len(index.buckets) for index in self._indexes.values()),
            max_bucket_size=max(
                (index.max_bucket_size for index in self._indexes.values()), default=0
            ),
            high_water_mark=self._high_water_mark,
            lookup_candidates_inspected=self._lookup_candidates_inspected,
            estimated_bytes=estimated_bytes,
        )


class PackedByteRowStore:
    """Fixed inline byte-row arena with compact reusable integer handles.

    Common small rows occupy slots in large contiguous bytearrays, preventing
    retained per-row ``bytes`` objects from pinning transient allocator arenas.
    Oversized rows use a rare exact overflow map. The store owns no semantic
    key map; callers compose it with :class:`PackedUniqueDigestMap` routes.
    """

    def __init__(self, *, inline_slot_bytes: int, chunk_slots: int = 256) -> None:
        if inline_slot_bytes <= 0 or inline_slot_bytes >= 1 << 16:
            raise ValueError("Packed byte-row inline slots must be between 1 and 65,535 bytes")
        if chunk_slots <= 0:
            raise ValueError("Packed byte-row chunk_slots must be positive")
        self._inline_slot_bytes = inline_slot_bytes
        self._chunk_slots = chunk_slots
        self._chunks: list[bytearray] = []
        self._lengths = array("H")
        self._active = bytearray()
        self._free_handles = array("I")
        self._overflow: dict[int, bytes] = {}
        self._overflow_bytes = 0
        self._chunk_bytes = 0
        self._live_count = 0
        self._high_water_mark = 0

    def __len__(self) -> int:
        return self._live_count

    def _ensure_chunk(self, handle: int) -> None:
        required = handle // self._chunk_slots + 1
        while len(self._chunks) < required:
            chunk = bytearray(self._inline_slot_bytes * self._chunk_slots)
            self._chunks.append(chunk)
            self._chunk_bytes += sys.getsizeof(chunk)

    def _slot(self, handle: int) -> tuple[int, int]:
        chunk_index, slot_index = divmod(handle, self._chunk_slots)
        return chunk_index, slot_index * self._inline_slot_bytes

    def insert(self, row: bytes) -> int:
        """Insert one immutable packed row and return its reusable handle."""

        if self._free_handles:
            handle = self._free_handles.pop()
        else:
            handle = len(self._lengths)
            self._lengths.append(0)
            self._active.append(0)
        self._ensure_chunk(handle)
        if len(row) <= self._inline_slot_bytes:
            chunk_index, offset = self._slot(handle)
            self._chunks[chunk_index][offset : offset + len(row)] = row
            self._lengths[handle] = len(row)
        else:
            self._overflow[handle] = row
            self._overflow_bytes += sys.getsizeof(row)
            self._lengths[handle] = 0
        self._active[handle] = 1
        self._live_count += 1
        self._high_water_mark = max(self._high_water_mark, self._live_count)
        return handle

    def get_by_handle(self, handle: int) -> bytes | memoryview:
        """Return one live immutable row view or raise ``KeyError``."""

        if handle < 0 or handle >= len(self._active) or not self._active[handle]:
            raise KeyError(handle)
        overflow = self._overflow.get(handle)
        if overflow is not None:
            return overflow
        chunk_index, offset = self._slot(handle)
        return memoryview(self._chunks[chunk_index])[offset : offset + self._lengths[handle]]

    def delete(self, handle: int) -> None:
        """Delete one live handle and release all arenas when the store empties."""

        self.get_by_handle(handle)
        overflow = self._overflow.pop(handle, None)
        if overflow is not None:
            self._overflow_bytes -= sys.getsizeof(overflow)
        self._active[handle] = 0
        self._lengths[handle] = 0
        self._free_handles.append(handle)
        self._live_count -= 1
        if self._live_count == 0:
            self._chunks.clear()
            self._lengths = array("H")
            self._active = bytearray()
            self._free_handles = array("I")
            self._overflow.clear()
            self._overflow_bytes = 0
            self._chunk_bytes = 0

    @property
    def estimated_value_bytes(self) -> int:
        """Return arena and overflow backing bytes without scanning rows."""

        return (
            sys.getsizeof(self._chunks)
            + self._chunk_bytes
            + sys.getsizeof(self._overflow)
            + self._overflow_bytes
        )

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return compact handle/index structure without traversing values."""

        estimated_bytes = 0
        if estimate_bytes:
            estimated_bytes = sum(
                sys.getsizeof(value)
                for value in (
                    self,
                    self._lengths,
                    self._active,
                    self._free_handles,
                )
            )
        return IndexMetrics(
            live_entries=self._live_count,
            backing_entries=len(self._active),
            stale_entries=len(self._free_handles),
            allocated_slots=len(self._active),
            high_water_mark=self._high_water_mark,
            estimated_bytes=estimated_bytes,
        )


class IncrementalExactMap(MutableMapping[K, V], Generic[K, V]):
    """Lean exact map with bounded active/retired dictionary rotation.

    Unlike :class:`CompactIndexedStore`, this structure owns no values-by-handle
    arrays or secondary indexes.  It is intended for exact semantic routes whose
    value is already a compact handle.  Rotation is caller-synchronized and
    migrates at most ``max_entries`` keys while lookups consult both maps.
    """

    _PRIMARY_COMPACT_MIN_PEAK = 4_096
    _PRIMARY_COMPACT_RATIO = 2

    def __init__(self) -> None:
        self._items: dict[K, V] = {}
        self._retired_items: dict[K, V] | None = None
        self._primary_peak_entries = 0
        self._high_water_mark = 0
        self._primary_compaction_rotations = 0
        self._primary_compaction_work = 0
        self._primary_compaction_seconds = 0.0

    def __getitem__(self, key: K) -> V:
        try:
            return self._items[key]
        except KeyError:
            retired = self._retired_items
            if retired is None:
                raise
            return retired[key]

    def __setitem__(self, key: K, value: V) -> None:
        retired = self._retired_items
        if retired is not None:
            retired.pop(key, None)
        self._items[key] = value
        live_entries = len(self)
        self._primary_peak_entries = max(self._primary_peak_entries, live_entries)
        self._high_water_mark = max(self._high_water_mark, live_entries)

    def __delitem__(self, key: K) -> None:
        try:
            del self._items[key]
            return
        except KeyError:
            retired = self._retired_items
            if retired is None:
                raise
        del retired[key]

    def __iter__(self) -> Iterator[K]:
        retired = self._retired_items
        if retired is None:
            return iter(self._items)
        return chain(self._items, retired)

    def __len__(self) -> int:
        return len(self._items) + (0 if self._retired_items is None else len(self._retired_items))

    def compact_primary(
        self,
        *,
        max_entries: int = 4_096,
        force: bool = False,
    ) -> int:
        """Rotate over-allocated backing maps with bounded per-call work."""

        if max_entries < 0:
            raise ValueError("IncrementalExactMap max_entries must be non-negative")
        started = perf_counter()
        retired = self._retired_items
        if retired is None:
            live_entries = len(self._items)
            amplified = (
                self._primary_peak_entries >= self._PRIMARY_COMPACT_MIN_PEAK
                and self._primary_peak_entries
                > max(
                    live_entries * self._PRIMARY_COMPACT_RATIO,
                    live_entries + self._PRIMARY_COMPACT_MIN_PEAK,
                )
            )
            if not force and not amplified:
                self._primary_compaction_seconds += perf_counter() - started
                return 0
            self._retired_items = self._items
            self._items = {}
            self._primary_peak_entries = 0
            retired = self._retired_items

        if not retired:
            self._retired_items = None
            self._primary_compaction_rotations += 1
            self._primary_peak_entries = len(self._items)
            self._primary_compaction_seconds += perf_counter() - started
            return 0

        work = min(max_entries, len(retired))
        for _ordinal in range(work):
            key, value = retired.popitem()
            self._items.setdefault(key, value)
        self._primary_compaction_work += work
        self._primary_peak_entries = max(self._primary_peak_entries, len(self._items))
        if not retired:
            self._retired_items = None
            self._primary_compaction_rotations += 1
            self._primary_peak_entries = len(self._items)
        self._primary_compaction_seconds += perf_counter() - started
        return work

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return exact-route map cardinality, capacity, and rotation metrics."""

        retired = self._retired_items
        live_entries = len(self)
        primary_map_backing_bytes = sys.getsizeof(self._items) + (
            0 if retired is None else sys.getsizeof(retired)
        )
        return IndexMetrics(
            live_entries=live_entries,
            backing_entries=live_entries,
            high_water_mark=self._high_water_mark,
            estimated_bytes=(
                sys.getsizeof(self) + primary_map_backing_bytes if estimate_bytes else 0
            ),
            primary_map_entries=live_entries,
            primary_map_backing_bytes=primary_map_backing_bytes,
            primary_compaction_pending=retired is not None,
            primary_compaction_rotations=self._primary_compaction_rotations,
            primary_compaction_work=self._primary_compaction_work,
            primary_compaction_seconds=self._primary_compaction_seconds,
        )


class IndexedEntityStore(MutableMapping[K, V], Generic[K, V]):
    """Insertion-ordered primary storage with synchronized equality indexes."""

    def __init__(self, **indexers: Callable[[V], Hashable]) -> None:
        """Create an empty store with named secondary-index extractors."""
        self._items: dict[K, V] = {}
        self._indexers = indexers
        self._indexes: dict[str, dict[Hashable, dict[K, None]]] = {name: {} for name in indexers}
        self._indexed_values: dict[K, dict[str, Hashable]] = {}

    def __getitem__(self, key: K) -> V:
        return self._items[key]

    def __setitem__(self, key: K, value: V) -> None:
        if key in self._items:
            self._remove_indexes(key)
        self._items[key] = value
        self._add_indexes(key, value)

    def __delitem__(self, key: K) -> None:
        self._remove_indexes(key)
        del self._items[key]

    def __iter__(self) -> Iterator[K]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def _add_indexes(self, key: K, value: V) -> None:
        indexed_values: dict[str, Hashable] = {}
        for name, extractor in self._indexers.items():
            indexed_value = extractor(value)
            indexed_values[name] = indexed_value
            self._indexes[name].setdefault(indexed_value, {})[key] = None
        self._indexed_values[key] = indexed_values

    def _remove_indexes(self, key: K) -> None:
        indexed_values = self._indexed_values.pop(key, {})
        for name, indexed_value in indexed_values.items():
            bucket = self._indexes[name].get(indexed_value)
            if bucket is None:
                continue
            bucket.pop(key, None)
            if not bucket:
                del self._indexes[name][indexed_value]

    def refresh(self, key: K) -> None:
        """Refresh secondary indexes after indexed fields mutate in place."""
        value = self._items[key]
        self._remove_indexes(key)
        self._add_indexes(key, value)

    def rekey(self, old_key: K, new_key: K) -> V:
        """Move an entity to a new primary key and return it."""
        value = self.pop(old_key)
        self[new_key] = value
        return value

    def find(self, index_name: str, indexed_value: Hashable) -> list[V]:
        """Return matching values in their index insertion order."""
        bucket = self._indexes[index_name].get(indexed_value, {})
        return [self._items[key] for key in bucket if key in self._items]

    def find_keys(self, index_name: str, indexed_value: Hashable) -> tuple[K, ...]:
        """Return matching primary keys in their index insertion order."""
        bucket = self._indexes[index_name].get(indexed_value, {})
        return tuple(key for key in bucket if key in self._items)


class ExpiringIndex(MutableMapping[K, V], Generic[K, V]):
    """Key/value storage with ordered deadline eviction and stale-heap repair."""

    _COMPACT_MIN_BACKING = 4_096
    _COMPACT_RATIO = 2

    def __init__(
        self,
        *,
        deadline: Callable[[V], float] | None = None,
    ) -> None:
        """Create an empty expiry index."""
        self._items: dict[K, V] = {}
        self._deadlines: dict[K, float] = {}
        self._orders: dict[K, int] = {}
        self._versions: dict[K, int] = {}
        self._heap: list[tuple[float, int, int, K]] = []
        self._retired_heap: list[tuple[float, int, int, K]] | None = None
        self._protected: set[K] = set()
        self._protected_high_water_mark = 0
        self._next_order = 0
        self._deadline_extractor = deadline
        self._high_water_mark = 0
        self._compaction_work = 0
        self._compaction_seconds = 0.0

    def __getitem__(self, key: K) -> V:
        return self._items[key]

    def __setitem__(self, key: K, value: V) -> None:
        if self._deadline_extractor is None:
            raise TypeError("ExpiringIndex assignment requires a deadline extractor")
        self.set(key, value, self._deadline_extractor(value))

    def __delitem__(self, key: K) -> None:
        if key not in self._items:
            raise KeyError(key)
        self.pop(key)

    def __iter__(self) -> Iterator[K]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return bool(self._items)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ExpiringIndex):
            return self._items == other._items
        if isinstance(other, MutableMapping):
            return self._items == dict(other)
        return False

    def get(self, key: K, default: V | None = None) -> V | None:
        """Return a value by key."""
        return self._items.get(key, default)

    def deadline(self, key: K) -> float | None:
        """Return the current deadline for a key."""
        return self._deadlines.get(key)

    def checkpoint_records(self) -> tuple[tuple[K, V, float, int, bool], ...]:
        """Return live semantic rows in stable insertion order for checkpointing."""

        return tuple(
            (
                key,
                self._items[key],
                self._deadlines[key],
                self._orders[key],
                key in self._protected,
            )
            for key in sorted(self._items, key=self._orders.__getitem__)
        )

    def restore_checkpoint_records(
        self,
        records: tuple[tuple[K, V, float, int, bool], ...],
    ) -> None:
        """Hydrate semantic rows into a fresh index and rebuild its expiry heap."""

        if self._items:
            raise ValueError("checkpoint index hydration requires a fresh empty index")
        prior_order = -1
        for key, value, deadline, order, protected in records:
            hash(key)
            if (
                key in self._items
                or type(order) is not int
                or order < 0
                or order <= prior_order
                or type(deadline) not in {int, float}
                or type(protected) is not bool
            ):
                raise ValueError("checkpoint index row is invalid or out of order")
            canonical_deadline = float(deadline)
            if math.isnan(canonical_deadline):
                raise ValueError("checkpoint index deadline cannot be NaN")
            self._items[key] = value
            self._deadlines[key] = canonical_deadline
            self._orders[key] = order
            self._versions[key] = 1
            if protected:
                self._protected.add(key)
            else:
                heapq.heappush(self._heap, (canonical_deadline, order, 1, key))
            prior_order = order
        self._next_order = prior_order + 1
        self._high_water_mark = len(self._items)
        self._protected_high_water_mark = len(self._protected)

    def set(self, key: K, value: V, deadline: float) -> None:
        """Insert or update a value and its sortable deadline."""
        if key not in self._orders:
            self._orders[key] = self._next_order
            self._next_order += 1
        version = self._versions.get(key, 0) + 1
        self._versions[key] = version
        self._items[key] = value
        self._deadlines[key] = deadline
        self._high_water_mark = max(self._high_water_mark, len(self._items))
        if key not in self._protected:
            heapq.heappush(
                self._heap,
                (deadline, self._orders[key], version, key),
            )

    def protect(self, key: K) -> bool:
        """Suspend one live key from expiry and capacity eviction.

        Protection preserves the exact value, deadline, and insertion order.
        The generation bump invalidates its prior heap record, which ordinary
        expiry or compaction will discard once without repeatedly inspecting
        the protected key.
        """

        if key not in self._items:
            raise KeyError(key)
        if key in self._protected:
            return False
        self._protected.add(key)
        self._protected_high_water_mark = max(
            self._protected_high_water_mark,
            len(self._protected),
        )
        self._versions[key] += 1
        return True

    def is_protected(self, key: K) -> bool:
        """Return whether one live key is suspended from heap eligibility."""

        return key in self._protected

    def protected_count(self) -> int:
        """Return the exact number of live protected keys."""

        return len(self._protected)

    def release(self, key: K) -> bool:
        """Requeue and release one protected key with a restart-safe tail.

        The future-version heap node is allocated first while protection still
        fences the key.  Only then do existing scalar/set entries flip to make
        that node live.  A caller retry after a lost successful return is an
        idempotent no-op and never queues another live generation.
        """

        if key not in self._items:
            raise KeyError(key)
        if key not in self._protected:
            return False
        deadline = self._deadlines[key]
        order = self._orders[key]
        release_version = self._versions[key] + 1
        heapq.heappush(
            self._heap,
            (deadline, order, release_version, key),
        )
        self._versions[key] = release_version
        self._protected.remove(key)
        return True

    def pop(self, key: K, default: V | None = None) -> V | None:
        """Remove a key while leaving any stale heap entry harmless."""
        if key not in self._items:
            return default
        value = self._items.pop(key)
        self._protected.discard(key)
        self._deadlines.pop(key, None)
        self._orders.pop(key, None)
        self._versions.pop(key, None)
        if not self._items:
            self._items = {}
            self._deadlines = {}
            self._orders = {}
            self._versions = {}
            self._heap = []
            self._retired_heap = None
            self._protected = set()
            self._next_order = 0
        return value

    def items(self) -> Iterator[tuple[K, V]]:
        """Iterate live items in primary insertion order."""
        return iter(self._items.items())

    def values(self) -> Iterator[V]:
        """Iterate live values in primary insertion order."""
        return iter(self._items.values())

    def expire_before_page(
        self,
        cutoff: float,
        *,
        inclusive: bool = False,
        limit: int = 4_096,
    ) -> tuple[tuple[K, V], ...]:
        """Remove one bounded due page in deterministic deadline/order order."""

        if limit <= 0:
            raise ValueError("ExpiringIndex expiry page limit must be positive")
        expired: list[tuple[K, V]] = []
        while len(expired) < limit:
            heap = self._earliest_heap()
            if heap is None:
                break
            deadline, order, version, key = heap[0]
            if deadline > cutoff or (deadline == cutoff and not inclusive):
                break
            heapq.heappop(heap)
            if (
                key in self._protected
                or self._versions.get(key) != version
                or self._deadlines.get(key) != deadline
                or self._orders.get(key) != order
            ):
                continue
            value = self.pop(key)
            if value is not None:
                expired.append((key, value))
        self._compact_heap_if_needed()
        return tuple(expired)

    def expire_before(
        self,
        cutoff: float,
        *,
        inclusive: bool = False,
    ) -> list[tuple[K, V]]:
        """Compatibility wrapper that explicitly materializes every due page."""

        expired: list[tuple[K, V]] = []
        while page := self.expire_before_page(
            cutoff,
            inclusive=inclusive,
            limit=4_096,
        ):
            expired.extend(page)
        return expired

    def trim(
        self,
        capacity: int,
        *,
        rank: Callable[[K, V], object],
        reverse: bool = True,
    ) -> list[tuple[K, V]]:
        """Retain the highest-ranked entries using stable insertion ordering."""
        if capacity < 0:
            raise ValueError("ExpiringIndex capacity must be non-negative")
        if capacity < len(self._protected):
            raise ValueError("ExpiringIndex capacity cannot be smaller than protected entries")
        if len(self._items) <= capacity:
            return []
        ranked = sorted(
            ((key, value) for key, value in self._items.items() if key not in self._protected),
            key=lambda item: rank(item[0], item[1]),
            reverse=reverse,
        )
        available = max(0, capacity - len(self._protected))
        retained = {key for key, _value in ranked[:available]}
        removed: list[tuple[K, V]] = []
        for key in tuple(self._items):
            if key in self._protected:
                continue
            if key in retained:
                continue
            value = self.pop(key)
            if value is not None:
                removed.append((key, value))
        self.compact()
        return removed

    def trim_earliest(self, capacity: int) -> list[tuple[K, V]]:
        """Evict the earliest-deadline entries in ``O(r log n)`` time.

        Use this for capacity bounds whose retention priority is already the
        expiry deadline. It avoids sorting the entire live index every time a
        high-volume workload crosses its cap.
        """

        if capacity < 0:
            raise ValueError("ExpiringIndex capacity must be non-negative")
        if capacity < len(self._protected):
            raise ValueError("ExpiringIndex capacity cannot be smaller than protected entries")
        removed: list[tuple[K, V]] = []
        while len(self._items) > capacity:
            heap = self._earliest_heap()
            if heap is None:
                break
            deadline, order, version, key = heapq.heappop(heap)
            if (
                key in self._protected
                or self._versions.get(key) != version
                or self._deadlines.get(key) != deadline
                or self._orders.get(key) != order
            ):
                continue
            value = self.pop(key)
            if value is not None:
                removed.append((key, value))
        self._compact_heap_if_needed()
        return removed

    def _compact_heap_if_needed(self) -> None:
        eligible_entries = len(self._items) - len(self._protected)
        if self._retired_heap is None and len(self._heap) > max(
            self._COMPACT_MIN_BACKING,
            eligible_entries * self._COMPACT_RATIO,
        ):
            self._retired_heap = self._heap
            self._heap = []

    def compact(self, *, max_entries: int = 4_096) -> int:
        """Incrementally rebuild stale deadline state at a watermark.

        At most ``max_entries`` records move out of the retired heap per call.
        Exact expiry continues to merge the active and retired heap minima, so
        callers never need a million-entry rebuild inside one critical section.
        """

        if max_entries < 0:
            raise ValueError("ExpiringIndex max_entries must be non-negative")
        started = perf_counter()
        eligible_entries = len(self._items) - len(self._protected)
        if self._retired_heap is None:
            if len(self._heap) <= eligible_entries:
                self._compaction_seconds += perf_counter() - started
                return 0
            self._retired_heap = self._heap
            self._heap = []

        retired = self._retired_heap
        work = 0
        while retired and work < max_entries:
            deadline, order, version, key = heapq.heappop(retired)
            work += 1
            if (
                key not in self._protected
                and self._versions.get(key) == version
                and self._deadlines.get(key) == deadline
                and self._orders.get(key) == order
            ):
                heapq.heappush(self._heap, (deadline, order, version, key))
        if not retired:
            self._retired_heap = None
        self._compaction_work += work
        self._compaction_seconds += perf_counter() - started
        return work

    def _earliest_heap(self) -> list[tuple[float, int, int, K]] | None:
        """Return the heap containing the globally earliest backing record."""

        retired = self._retired_heap
        if retired is not None and not retired:
            self._retired_heap = None
            retired = None
        if not self._heap:
            return retired if retired else None
        if not retired:
            return self._heap
        if retired[0][:3] < self._heap[0][:3]:
            return retired
        return self._heap

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return live and stale deadline cardinality."""
        estimated_bytes = 0
        if estimate_bytes:
            estimated_bytes = sum(
                sys.getsizeof(value)
                for value in (
                    self,
                    self._items,
                    self._deadlines,
                    self._orders,
                    self._versions,
                    self._heap,
                    self._protected,
                )
            )
            if self._retired_heap is not None:
                estimated_bytes += sys.getsizeof(self._retired_heap)
            estimated_bytes += sum(sys.getsizeof(entry) for entry in self._heap)
            estimated_bytes += sum(sys.getsizeof(key) for key in self._protected)
            if self._retired_heap is not None:
                estimated_bytes += sum(sys.getsizeof(entry) for entry in self._retired_heap)
        backing_entries = len(self._heap) + (
            0 if self._retired_heap is None else len(self._retired_heap)
        )
        eligible_entries = len(self._items) - len(self._protected)
        return IndexMetrics(
            live_entries=len(self._items),
            backing_entries=backing_entries,
            stale_entries=max(0, backing_entries - eligible_entries),
            high_water_mark=self._high_water_mark,
            compaction_work=self._compaction_work,
            compaction_seconds=self._compaction_seconds,
            compaction_pending=self._retired_heap is not None,
            estimated_bytes=estimated_bytes,
            protected_entries=len(self._protected),
            protected_high_water_mark=self._protected_high_water_mark,
        )


class _PackedDeadlineHeap:
    """Binary min-heap stored in parallel primitive arrays."""

    __slots__ = ("deadlines", "handles", "versions")

    def __init__(self) -> None:
        self.deadlines = array("q")
        self.versions = array("I")
        self.handles = array("I")

    def __len__(self) -> int:
        return len(self.deadlines)

    def _key(self, position: int) -> tuple[int, int, int]:
        return (
            self.deadlines[position],
            self.handles[position],
            self.versions[position],
        )

    def _swap(self, left: int, right: int) -> None:
        self.deadlines[left], self.deadlines[right] = (
            self.deadlines[right],
            self.deadlines[left],
        )
        self.versions[left], self.versions[right] = (
            self.versions[right],
            self.versions[left],
        )
        self.handles[left], self.handles[right] = (
            self.handles[right],
            self.handles[left],
        )

    def push(self, deadline_us: int, version: int, handle: int) -> None:
        """Push one primitive deadline record in logarithmic time."""

        self.deadlines.append(deadline_us)
        self.versions.append(version)
        self.handles.append(handle)
        position = len(self.deadlines) - 1
        while position:
            parent = (position - 1) // 2
            if self._key(parent) <= self._key(position):
                break
            self._swap(parent, position)
            position = parent

    def peek(self) -> tuple[int, int, int]:
        """Return the earliest record without removing it."""

        if not self.deadlines:
            raise IndexError("peek from empty packed deadline heap")
        return self.deadlines[0], self.versions[0], self.handles[0]

    def pop(self) -> tuple[int, int, int]:
        """Remove and return the earliest primitive deadline record."""

        if not self.deadlines:
            raise IndexError("pop from empty packed deadline heap")
        root = self.peek()
        last_deadline = self.deadlines.pop()
        last_version = self.versions.pop()
        last_handle = self.handles.pop()
        if not self.deadlines:
            return root
        self.deadlines[0] = last_deadline
        self.versions[0] = last_version
        self.handles[0] = last_handle
        position = 0
        size = len(self.deadlines)
        while True:
            left = position * 2 + 1
            if left >= size:
                break
            right = left + 1
            child = right if right < size and self._key(right) < self._key(left) else left
            if self._key(position) <= self._key(child):
                break
            self._swap(position, child)
            position = child
        return root

    def estimated_bytes(self) -> int:
        """Return primitive-array backing bytes without traversing entries."""

        return sum(
            sys.getsizeof(value) for value in (self, self.deadlines, self.versions, self.handles)
        )


class PackedHandleExpiryIndex:
    """Versioned handle deadlines backed by primitive arrays, not Python dicts.

    Handles must be compact non-negative integers owned by a colocated store.
    Deadline updates append versioned heap records; stale amplification rotates
    into a retired heap in O(1), then rebuilds by scanning at most ``max_slots``
    handle slots per explicit compaction call.
    """

    _MISSING_DEADLINE = -(1 << 63)
    _COMPACT_MIN_BACKING = 4_096
    _COMPACT_RATIO = 2
    _MAX_VERSION = (1 << 32) - 1

    def __init__(self) -> None:
        self._deadlines = array("q")
        self._versions = array("I")
        self._heap = _PackedDeadlineHeap()
        self._retired_heap: _PackedDeadlineHeap | None = None
        self._compaction_cursor = 0
        self._live_count = 0
        self._high_water_mark = 0
        self._compaction_work = 0
        self._compaction_seconds = 0.0

    @staticmethod
    def _to_microseconds(deadline: float) -> int:
        deadline_us = round(deadline * 1_000_000)
        if deadline_us <= PackedHandleExpiryIndex._MISSING_DEADLINE:
            raise ValueError("PackedHandleExpiryIndex deadline is outside int64 range")
        return deadline_us

    @staticmethod
    def _to_seconds(deadline_us: int) -> float:
        return deadline_us / 1_000_000

    def __len__(self) -> int:
        return self._live_count

    def _ensure_handle(self, handle: int) -> None:
        if handle < 0 or handle >= (1 << 32):
            raise ValueError("PackedHandleExpiryIndex handle must fit uint32")
        missing = handle + 1 - len(self._deadlines)
        if missing <= 0:
            return
        self._deadlines.extend(array("q", [self._MISSING_DEADLINE]) * missing)
        self._versions.extend(array("I", [0]) * missing)

    def set(self, handle: int, deadline: float) -> None:
        """Insert or update one handle deadline in logarithmic time."""

        self._ensure_handle(handle)
        if self._versions[handle] == self._MAX_VERSION:
            raise OverflowError("PackedHandleExpiryIndex exhausted a handle version")
        if self._deadlines[handle] == self._MISSING_DEADLINE:
            self._live_count += 1
            self._high_water_mark = max(self._high_water_mark, self._live_count)
        version = self._versions[handle] + 1
        deadline_us = self._to_microseconds(deadline)
        self._versions[handle] = version
        self._deadlines[handle] = deadline_us
        self._heap.push(deadline_us, version, handle)

    def get(self, handle: int, default: float | None = None) -> float | None:
        """Return one current handle deadline without touching heap state."""

        if handle < 0 or handle >= len(self._deadlines):
            return default
        deadline_us = self._deadlines[handle]
        if deadline_us == self._MISSING_DEADLINE:
            return default
        return self._to_seconds(deadline_us)

    def pop(self, handle: int, default: float | None = None) -> float | None:
        """Remove one live handle while leaving its heap records version-stale."""

        if handle < 0 or handle >= len(self._deadlines):
            return default
        deadline_us = self._deadlines[handle]
        if deadline_us == self._MISSING_DEADLINE:
            return default
        self._deadlines[handle] = self._MISSING_DEADLINE
        self._live_count -= 1
        if self._live_count == 0:
            self._heap = _PackedDeadlineHeap()
            self._retired_heap = None
            self._compaction_cursor = 0
        return self._to_seconds(deadline_us)

    def _earliest_heap(self) -> _PackedDeadlineHeap | None:
        retired = self._retired_heap
        if retired is not None and not len(retired):
            self._retired_heap = None
            retired = None
        if not len(self._heap):
            return retired if retired is not None and len(retired) else None
        if retired is None or not len(retired):
            return self._heap
        return retired if retired.peek() < self._heap.peek() else self._heap

    def first_due_before(
        self,
        cutoff: float,
        *,
        inclusive: bool = False,
    ) -> tuple[int, float] | None:
        """Return the first current due handle without removing live state."""

        cutoff_us = self._to_microseconds(cutoff)
        while True:
            heap = self._earliest_heap()
            if heap is None:
                self._start_compaction_if_needed()
                return None
            deadline_us, version, handle = heap.peek()
            if (
                handle >= len(self._deadlines)
                or self._deadlines[handle] != deadline_us
                or self._versions[handle] != version
            ):
                heap.pop()
                continue
            self._start_compaction_if_needed()
            if deadline_us > cutoff_us or (deadline_us == cutoff_us and not inclusive):
                return None
            return handle, self._to_seconds(deadline_us)

    def expire_before_page(
        self,
        cutoff: float,
        *,
        inclusive: bool = False,
        limit: int = 4_096,
    ) -> tuple[tuple[int, float], ...]:
        """Remove one bounded due page in deadline/handle order."""

        if limit <= 0:
            raise ValueError("PackedHandleExpiryIndex expiry page limit must be positive")
        cutoff_us = self._to_microseconds(cutoff)
        expired: list[tuple[int, float]] = []
        while len(expired) < limit:
            heap = self._earliest_heap()
            if heap is None:
                break
            deadline_us, version, handle = heap.peek()
            if deadline_us > cutoff_us or (deadline_us == cutoff_us and not inclusive):
                break
            heap.pop()
            if (
                handle >= len(self._deadlines)
                or self._deadlines[handle] != deadline_us
                or self._versions[handle] != version
            ):
                continue
            value = self.pop(handle)
            if value is not None:
                expired.append((handle, value))
        self._start_compaction_if_needed()
        return tuple(expired)

    def expire_before(
        self,
        cutoff: float,
        *,
        inclusive: bool = False,
    ) -> list[tuple[int, float]]:
        """Compatibility wrapper that explicitly materializes every due page."""

        expired: list[tuple[int, float]] = []
        while page := self.expire_before_page(
            cutoff,
            inclusive=inclusive,
            limit=4_096,
        ):
            expired.extend(page)
        return expired

    def _start_compaction_if_needed(self, *, force: bool = False) -> None:
        if self._retired_heap is not None:
            return
        backing = len(self._heap)
        if not force and backing <= max(
            self._COMPACT_MIN_BACKING,
            self._live_count * self._COMPACT_RATIO,
        ):
            return
        self._retired_heap = self._heap
        self._heap = _PackedDeadlineHeap()
        self._compaction_cursor = 0

    def compact(self, *, max_slots: int = 4_096, force: bool = False) -> int:
        """Incrementally rebuild stale heap state from current handle slots."""

        if max_slots < 0:
            raise ValueError("PackedHandleExpiryIndex max_slots must be non-negative")
        started = perf_counter()
        self._start_compaction_if_needed(force=force)
        retired = self._retired_heap
        if retired is None:
            self._compaction_seconds += perf_counter() - started
            return 0
        if self._live_count == 0:
            self._retired_heap = None
            self._compaction_cursor = 0
            self._compaction_seconds += perf_counter() - started
            return 0
        stop = min(len(self._deadlines), self._compaction_cursor + max_slots)
        work = stop - self._compaction_cursor
        for handle in range(self._compaction_cursor, stop):
            deadline_us = self._deadlines[handle]
            if deadline_us == self._MISSING_DEADLINE:
                continue
            self._heap.push(deadline_us, self._versions[handle], handle)
        self._compaction_cursor = stop
        self._compaction_work += work
        if stop == len(self._deadlines):
            self._retired_heap = None
            self._compaction_cursor = 0
        self._compaction_seconds += perf_counter() - started
        return work

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return live/stale heap cardinality and primitive backing bytes."""

        backing_entries = len(self._heap) + (
            0 if self._retired_heap is None else len(self._retired_heap)
        )
        estimated_bytes = 0
        if estimate_bytes:
            estimated_bytes = (
                sys.getsizeof(self)
                + sys.getsizeof(self._deadlines)
                + sys.getsizeof(self._versions)
                + self._heap.estimated_bytes()
                + (0 if self._retired_heap is None else self._retired_heap.estimated_bytes())
            )
        return IndexMetrics(
            live_entries=self._live_count,
            backing_entries=backing_entries,
            stale_entries=max(0, backing_entries - self._live_count),
            allocated_slots=len(self._deadlines),
            high_water_mark=self._high_water_mark,
            compaction_work=self._compaction_work,
            compaction_seconds=self._compaction_seconds,
            compaction_pending=self._retired_heap is not None,
            estimated_bytes=estimated_bytes,
        )


class ShardedExpiringIndex(Generic[K, V]):
    """Lazy deterministic shards around deadline indexes.

    The caller supplies a stable integer shard selector, normally derived from
    host, owner, or source-instance identity. Only used shards are allocated,
    so small scenarios retain the low overhead of one ``ExpiringIndex`` while
    large registries bound individual heap rebuilds.
    """

    def __init__(
        self,
        *,
        shard_selector: Callable[[K], int],
        shard_count: int = 64,
        deadline: Callable[[V], float] | None = None,
    ) -> None:
        """Create a lazily sharded deadline index."""
        if shard_count <= 0:
            raise ValueError("ShardedExpiringIndex shard_count must be positive")
        self._selector = shard_selector
        self._shard_count = shard_count
        self._deadline_extractor = deadline
        self._shards: dict[int, ExpiringIndex[K, V]] = {}
        self._live_count = 0
        self._high_water_mark = 0

    def __len__(self) -> int:
        return self._live_count

    def __iter__(self) -> Iterator[K]:
        for shard_id in sorted(self._shards):
            yield from self._shards[shard_id]

    def _shard_id(self, key: K) -> int:
        return self._selector(key) % self._shard_count

    def _shard(self, key: K, *, create: bool) -> ExpiringIndex[K, V] | None:
        shard_id = self._shard_id(key)
        shard = self._shards.get(shard_id)
        if shard is None and create:
            shard = ExpiringIndex(deadline=self._deadline_extractor)
            self._shards[shard_id] = shard
        return shard

    def set(self, key: K, value: V, deadline: float) -> None:
        """Insert or replace a value in its stable shard."""
        shard = self._shard(key, create=True)
        assert shard is not None
        is_new = key not in shard
        shard.set(key, value, deadline)
        if is_new:
            self._live_count += 1
            self._high_water_mark = max(self._high_water_mark, self._live_count)

    def get(self, key: K, default: V | None = None) -> V | None:
        """Return a value through one exact shard lookup."""
        shard = self._shard(key, create=False)
        return default if shard is None else shard.get(key, default)

    def deadline(self, key: K) -> float | None:
        """Return the exact current deadline for a key."""
        shard = self._shard(key, create=False)
        return None if shard is None else shard.deadline(key)

    def pop(self, key: K, default: V | None = None) -> V | None:
        """Remove a value without scanning unrelated shards."""
        shard_id = self._shard_id(key)
        shard = self._shards.get(shard_id)
        if shard is None:
            return default
        existed = key in shard
        value = shard.pop(key, default)
        if existed:
            self._live_count -= 1
        if not shard:
            self._shards.pop(shard_id, None)
        return value

    def expire_before_page(
        self,
        cutoff: float,
        *,
        inclusive: bool = False,
        limit: int = 4_096,
    ) -> tuple[tuple[K, V], ...]:
        """Expire one globally bounded page across stable shard order."""

        if limit <= 0:
            raise ValueError("ShardedExpiringIndex expiry page limit must be positive")
        expired: list[tuple[K, V]] = []
        for shard_id in sorted(tuple(self._shards)):
            remaining = limit - len(expired)
            if remaining <= 0:
                break
            shard = self._shards[shard_id]
            shard_expired = shard.expire_before_page(
                cutoff,
                inclusive=inclusive,
                limit=remaining,
            )
            expired.extend(shard_expired)
            self._live_count -= len(shard_expired)
            if not shard:
                self._shards.pop(shard_id, None)
        return tuple(expired)

    def expire_before(
        self,
        cutoff: float,
        *,
        inclusive: bool = False,
    ) -> list[tuple[K, V]]:
        """Compatibility wrapper that explicitly materializes every due page."""

        expired: list[tuple[K, V]] = []
        while page := self.expire_before_page(
            cutoff,
            inclusive=inclusive,
            limit=4_096,
        ):
            expired.extend(page)
        return expired

    def compact(self, *, max_entries_per_shard: int = 4_096) -> int:
        """Incrementally compact every live shard at an explicit watermark."""

        if max_entries_per_shard < 0:
            raise ValueError("ShardedExpiringIndex max_entries_per_shard must be non-negative")
        return sum(
            shard.compact(max_entries=max_entries_per_shard) for shard in self._shards.values()
        )

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return aggregate shard metrics."""
        metrics = [shard.metrics(estimate_bytes=estimate_bytes) for shard in self._shards.values()]
        return IndexMetrics(
            live_entries=sum(metric.live_entries for metric in metrics),
            backing_entries=sum(metric.backing_entries for metric in metrics),
            stale_entries=sum(metric.stale_entries for metric in metrics),
            secondary_buckets=len(self._shards),
            max_bucket_size=max((metric.live_entries for metric in metrics), default=0),
            high_water_mark=self._high_water_mark,
            compaction_work=sum(metric.compaction_work for metric in metrics),
            compaction_seconds=sum(metric.compaction_seconds for metric in metrics),
            compaction_pending=any(metric.compaction_pending for metric in metrics),
            estimated_bytes=(
                sys.getsizeof(self) + sys.getsizeof(self._shards) if estimate_bytes else 0
            )
            + sum(metric.estimated_bytes for metric in metrics),
        )


class GroupedTemporalIndex(Generic[G, K]):
    """Persistent per-group time index with ordered range lookup."""

    def __init__(self) -> None:
        """Create an empty grouped temporal index."""
        self._records: dict[G, list[tuple[datetime, int, int, K]]] = {}
        self._current: dict[K, tuple[G, datetime, int, int]] = {}
        self._stale_counts: dict[G, int] = {}
        self._next_sequence = 0

    def add(self, key: K, group: G, event_time: datetime) -> None:
        """Add or replace a key's temporal record."""
        prior = self._current.get(key)
        version = (prior[3] + 1) if prior is not None else 1
        sequence = prior[2] if prior is not None else self._next_sequence
        if prior is None:
            self._next_sequence += 1
        else:
            prior_group = prior[0]
            self._stale_counts[prior_group] = self._stale_counts.get(prior_group, 0) + 1
        record = (event_time, sequence, version, key)
        records = self._records.setdefault(group, [])
        position = bisect_right(records, (event_time, math.inf, math.inf))
        records.insert(position, record)
        self._current[key] = (group, event_time, sequence, version)
        if prior is not None:
            self._compact_group_if_needed(prior[0])

    def remove(self, key: K) -> None:
        """Make a key's existing temporal records stale."""
        prior = self._current.pop(key, None)
        if prior is None:
            return
        group = prior[0]
        self._stale_counts[group] = self._stale_counts.get(group, 0) + 1
        self._compact_group_if_needed(group)

    def _compact_group_if_needed(self, group: G) -> None:
        """Discard stale records when they materially outweigh useful history."""

        stale_count = self._stale_counts.get(group, 0)
        records = self._records.get(group, [])
        if stale_count < 1024 or stale_count * 2 < len(records):
            return
        compacted = [
            record
            for record in records
            if self._current.get(record[3]) == (group, record[0], record[1], record[2])
        ]
        if compacted:
            self._records[group] = compacted
        else:
            self._records.pop(group, None)
        self._stale_counts.pop(group, None)

    def keys_after(self, group: G, cutoff: datetime) -> tuple[K, ...]:
        """Return current keys strictly after a cutoff in insertion order."""
        records = self._records.get(group, [])
        position = bisect_right(records, (cutoff, math.inf, math.inf))
        matches = [
            (sequence, key)
            for event_time, sequence, version, key in records[position:]
            if self._current.get(key) == (group, event_time, sequence, version)
        ]
        matches.sort()
        return tuple(key for _sequence, key in matches)

    def keys_at_or_before(self, group: G, cutoff: datetime) -> tuple[K, ...]:
        """Return current keys at or before a cutoff in insertion order."""
        records = self._records.get(group, [])
        position = bisect_right(records, (cutoff, math.inf, math.inf))
        matches = [
            (sequence, key)
            for event_time, sequence, version, key in records[:position]
            if self._current.get(key) == (group, event_time, sequence, version)
        ]
        matches.sort()
        return tuple(key for _sequence, key in matches)


@dataclass(slots=True)
class _PackedTemporalBlock:
    """Parallel packed arrays for one bounded temporal block."""

    times_us: array[int] = field(default_factory=lambda: array("q"))
    sequences: array[int] = field(default_factory=lambda: array("Q"))
    versions: array[int] = field(default_factory=lambda: array("I"))
    handles: array[int] = field(default_factory=lambda: array("Q"))

    def __len__(self) -> int:
        return len(self.handles)

    def append(self, time_us: int, sequence: int, version: int, handle: int) -> None:
        self.times_us.append(time_us)
        self.sequences.append(sequence)
        self.versions.append(version)
        self.handles.append(handle)

    def insert(self, position: int, time_us: int, sequence: int, version: int, handle: int) -> None:
        self.times_us.insert(position, time_us)
        self.sequences.insert(position, sequence)
        self.versions.insert(position, version)
        self.handles.insert(position, handle)

    def slice(self, start: int, stop: int | None = None) -> _PackedTemporalBlock:
        return _PackedTemporalBlock(
            times_us=self.times_us[start:stop],
            sequences=self.sequences[start:stop],
            versions=self.versions[start:stop],
            handles=self.handles[start:stop],
        )


@dataclass(slots=True)
class _SegmentedTemporalGroup:
    """Mutable fixed-size packed blocks for one equality partition."""

    blocks: list[_PackedTemporalBlock] = field(default_factory=list)
    block_last_times_us: array[int] = field(default_factory=lambda: array("q"))
    block_last_sequences: array[int] = field(default_factory=lambda: array("Q"))
    backing_count: int = 0
    live_count: int = 0
    stale_count: int = 0


class SegmentedTemporalIndex(Generic[G]):
    """Packed grouped temporal records keyed by compact integer handles.

    Semantic IDs belong in ``CompactIndexedStore``; this index stores only its
    dense handles. Results are yielded in canonical time order. Replacements
    leave versioned stale records until explicit watermark compaction.
    """

    BLOCK_SIZE = 256
    """Target number of packed records per sorted temporal block."""

    MAX_BLOCK_SIZE = BLOCK_SIZE * 2
    """Maximum observable block size after a completed mutation."""

    _BLOCK_SIZE = BLOCK_SIZE
    _EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

    def __init__(self, *, track_lookup_candidates: bool = False) -> None:
        """Create an empty packed segmented temporal index."""
        self._groups: list[_SegmentedTemporalGroup | object | None] = []
        self._group_ids: dict[G, int] = {}
        self._group_keys: list[G | object] = []
        self._free_group_ids: list[int] = []
        self._inline_handles = array("q")
        self._current_groups = array("I")
        self._current_times_us = array("q")
        self._current_sequences = array("Q")
        self._current_versions = array("I")
        self._active = bytearray()
        self._next_sequence = 0
        self._live_count = 0
        self._compaction_cursor = 0
        self._discard_cursor = 0
        self._backing_count = 0
        self._bucket_size_counts: dict[int, int] = {}
        self._max_bucket_size = 0
        self._track_lookup_candidates = track_lookup_candidates
        self._lookup_candidates_inspected = 0
        self._high_water_mark = 0
        self._compaction_work = 0
        self._compaction_seconds = 0.0

    def __len__(self) -> int:
        return self._live_count

    @classmethod
    def _time_us(cls, event_time: datetime) -> int:
        if event_time.utcoffset() is None:
            raise ValueError("SegmentedTemporalIndex requires timezone-aware timestamps")
        delta = event_time.astimezone(UTC) - cls._EPOCH
        return ((delta.days * 86_400) + delta.seconds) * 1_000_000 + delta.microseconds

    def _ensure_handle(self, handle: int) -> None:
        if handle < 0:
            raise ValueError("SegmentedTemporalIndex handle must be non-negative")
        missing = handle + 1 - len(self._active)
        if missing <= 0:
            return
        self._current_groups.extend(array("I", [0]) * missing)
        self._current_times_us.extend(array("q", [0]) * missing)
        self._current_sequences.extend(array("Q", [0]) * missing)
        self._current_versions.extend(array("I", [0]) * missing)
        self._active.extend(b"\x00" * missing)

    def _group_id(self, group: G) -> int:
        group_id = self._group_ids.get(group)
        if group_id is not None:
            return group_id
        if self._free_group_ids:
            group_id = self._free_group_ids.pop()
            self._groups[group_id] = _INLINE_TEMPORAL_GROUP
            self._group_keys[group_id] = group
            self._inline_handles[group_id] = -1
        else:
            group_id = len(self._groups)
            self._group_keys.append(group)
            self._groups.append(_INLINE_TEMPORAL_GROUP)
            self._inline_handles.append(-1)
        self._group_ids[group] = group_id
        return group_id

    def _adjust_group_backing(self, old_size: int, new_size: int) -> None:
        if old_size:
            old_count = self._bucket_size_counts[old_size] - 1
            if old_count:
                self._bucket_size_counts[old_size] = old_count
            else:
                del self._bucket_size_counts[old_size]
        if new_size:
            self._bucket_size_counts[new_size] = self._bucket_size_counts.get(new_size, 0) + 1
        self._backing_count += new_size - old_size
        self._max_bucket_size = max(self._max_bucket_size, new_size)
        if self._max_bucket_size not in self._bucket_size_counts:
            # The number of distinct positive bucket sizes is O(sqrt(n)) for
            # n backing records. Recompute over those classes instead of
            # decrementing once per discarded record in a formerly huge group.
            self._max_bucket_size = max(self._bucket_size_counts, default=0)

    def _release_group(self, group_id: int) -> None:
        group = self._groups[group_id]
        if group is None:
            return
        if group is _INLINE_TEMPORAL_GROUP:
            prior_backing = 1 if self._inline_handles[group_id] >= 0 else 0
            self._inline_handles[group_id] = -1
        else:
            assert isinstance(group, _SegmentedTemporalGroup)
            if group.live_count:
                raise AssertionError("cannot release a temporal group with live handles")
            prior_backing = group.backing_count
            group.backing_count = 0
        if prior_backing:
            self._adjust_group_backing(prior_backing, 0)
        group_key = self._group_keys[group_id]
        if group_key is not _MISSING:
            self._group_ids.pop(cast(G, group_key), None)
        self._groups[group_id] = None
        self._group_keys[group_id] = _MISSING
        self._free_group_ids.append(group_id)

    def _promote_inline_group(self, group_id: int) -> _SegmentedTemporalGroup:
        handle = self._inline_handles[group_id]
        if handle < 0:
            raise AssertionError("cannot promote an empty inline temporal group")
        group = _SegmentedTemporalGroup(live_count=1)
        self._insert_record(
            group,
            self._current_times_us[handle],
            self._current_sequences[handle],
            self._current_versions[handle],
            handle,
        )
        self._groups[group_id] = group
        self._inline_handles[group_id] = -1
        return group

    def add(self, handle: int, group: G, event_time: datetime) -> None:
        """Add or atomically replace a compact handle's temporal record."""
        self._ensure_handle(handle)
        time_us = self._time_us(event_time)
        was_active = bool(self._active[handle])
        prior_group_id = self._current_groups[handle] if was_active else None
        if was_active:
            sequence = self._current_sequences[handle]
            version = self._current_versions[handle] + 1
        else:
            sequence = self._next_sequence
            self._next_sequence += 1
            version = self._current_versions[handle] + 1
            self._live_count += 1
            self._high_water_mark = max(self._high_water_mark, self._live_count)

        group_id = self._group_id(group)
        if prior_group_id is not None:
            prior_group = self._groups[prior_group_id]
            assert prior_group is not None
            if prior_group_id == group_id:
                if prior_group is _INLINE_TEMPORAL_GROUP:
                    prior_group = self._promote_inline_group(group_id)
                assert isinstance(prior_group, _SegmentedTemporalGroup)
                prior_group.stale_count += 1
            elif prior_group is _INLINE_TEMPORAL_GROUP:
                self._release_group(prior_group_id)
            else:
                assert isinstance(prior_group, _SegmentedTemporalGroup)
                prior_group.stale_count += 1
                prior_group.live_count -= 1
                if prior_group.live_count == 0:
                    self._release_group(prior_group_id)

        group_state = self._groups[group_id]
        assert group_state is not None
        is_new_membership = prior_group_id is None or prior_group_id != group_id
        if group_state is _INLINE_TEMPORAL_GROUP and self._inline_handles[group_id] < 0:
            self._inline_handles[group_id] = handle
            self._adjust_group_backing(0, 1)
        else:
            if group_state is _INLINE_TEMPORAL_GROUP:
                group_state = self._promote_inline_group(group_id)
            assert isinstance(group_state, _SegmentedTemporalGroup)
            if is_new_membership:
                group_state.live_count += 1
            prior_backing = group_state.backing_count
            self._insert_record(group_state, time_us, sequence, version, handle)
            self._adjust_group_backing(prior_backing, group_state.backing_count)
        self._current_groups[handle] = group_id
        self._current_times_us[handle] = time_us
        self._current_sequences[handle] = sequence
        self._current_versions[handle] = version
        self._active[handle] = 1

    def _insert_record(
        self,
        group: _SegmentedTemporalGroup,
        time_us: int,
        sequence: int,
        version: int,
        handle: int,
    ) -> None:
        group.backing_count += 1
        if not group.blocks:
            block = _PackedTemporalBlock()
            block.append(time_us, sequence, version, handle)
            group.blocks.append(block)
            group.block_last_times_us.append(time_us)
            group.block_last_sequences.append(sequence)
            return

        last_block = group.blocks[-1]
        if (time_us, sequence) >= (last_block.times_us[-1], last_block.sequences[-1]):
            block_index = len(group.blocks) - 1
            group.blocks[block_index].append(time_us, sequence, version, handle)
        else:
            first_equal_end = bisect_left(group.block_last_times_us, time_us)
            after_equal_end = bisect_right(group.block_last_times_us, time_us)
            block_index = bisect_right(
                group.block_last_sequences,
                sequence,
                first_equal_end,
                after_equal_end,
            )
            if block_index >= len(group.blocks):
                block_index = len(group.blocks) - 1
            block = group.blocks[block_index]
            first_equal = bisect_left(block.times_us, time_us)
            after_equal = bisect_right(block.times_us, time_us)
            position = bisect_right(block.sequences, sequence, first_equal, after_equal)
            block.insert(position, time_us, sequence, version, handle)
        group.block_last_times_us[block_index] = group.blocks[block_index].times_us[-1]
        group.block_last_sequences[block_index] = group.blocks[block_index].sequences[-1]
        if len(group.blocks[block_index]) > self._BLOCK_SIZE * 2:
            self._split_block(group, block_index)

    @staticmethod
    def _split_block(group: _SegmentedTemporalGroup, block_index: int) -> None:
        block = group.blocks[block_index]
        midpoint = len(block) // 2
        left = block.slice(0, midpoint)
        right = block.slice(midpoint)
        group.blocks[block_index : block_index + 1] = [left, right]
        group.block_last_times_us[block_index : block_index + 1] = array(
            "q", [left.times_us[-1], right.times_us[-1]]
        )
        group.block_last_sequences[block_index : block_index + 1] = array(
            "Q", [left.sequences[-1], right.sequences[-1]]
        )

    def remove(self, handle: int) -> None:
        """Remove a live handle while deferring physical compaction."""
        if handle < 0 or handle >= len(self._active) or not self._active[handle]:
            return
        group = self._groups[self._current_groups[handle]]
        assert group is not None
        self._active[handle] = 0
        self._live_count -= 1
        group_id = self._current_groups[handle]
        if group is _INLINE_TEMPORAL_GROUP:
            self._release_group(group_id)
            return
        assert isinstance(group, _SegmentedTemporalGroup)
        group.stale_count += 1
        group.live_count -= 1
        if group.live_count == 0:
            self._release_group(group_id)

    def _is_current(
        self,
        group_id: int,
        block: _PackedTemporalBlock,
        position: int,
    ) -> bool:
        handle = block.handles[position]
        return bool(
            handle < len(self._active)
            and self._active[handle]
            and self._current_groups[handle] == group_id
            and self._current_times_us[handle] == block.times_us[position]
            and self._current_sequences[handle] == block.sequences[position]
            and self._current_versions[handle] == block.versions[position]
        )

    def _tracked_is_current(
        self,
        group_id: int,
        block: _PackedTemporalBlock,
        position: int,
    ) -> bool:
        self._lookup_candidates_inspected += 1
        return self._is_current(group_id, block, position)

    def iter_after(
        self,
        group: G,
        cutoff: datetime,
        *,
        limit: int | None = None,
    ) -> Iterator[int]:
        """Yield current handles strictly after a cutoff in temporal order."""
        if limit is not None and limit < 0:
            raise ValueError("SegmentedTemporalIndex limit must be non-negative")
        group_id = self._group_ids.get(group)
        if group_id is None or limit == 0:
            return
        cutoff_us = self._time_us(cutoff)
        group_state = self._groups[group_id]
        assert group_state is not None
        if group_state is _INLINE_TEMPORAL_GROUP:
            handle = self._inline_handles[group_id]
            if self._track_lookup_candidates:
                self._lookup_candidates_inspected += 1
            if handle >= 0 and self._current_times_us[handle] > cutoff_us:
                yield handle
            return
        assert isinstance(group_state, _SegmentedTemporalGroup)
        start_block = bisect_right(group_state.block_last_times_us, cutoff_us)
        yielded = 0
        is_current = self._tracked_is_current if self._track_lookup_candidates else self._is_current
        for block_index in range(start_block, len(group_state.blocks)):
            block = group_state.blocks[block_index]
            position = bisect_right(block.times_us, cutoff_us)
            for index in range(position, len(block)):
                if not is_current(group_id, block, index):
                    continue
                yield block.handles[index]
                yielded += 1
                if limit is not None and yielded >= limit:
                    return

    def iter_at_or_before(
        self,
        group: G,
        cutoff: datetime,
        *,
        limit: int | None = None,
    ) -> Iterator[int]:
        """Yield current handles at or before a cutoff in temporal order."""
        if limit is not None and limit < 0:
            raise ValueError("SegmentedTemporalIndex limit must be non-negative")
        group_id = self._group_ids.get(group)
        if group_id is None or limit == 0:
            return
        cutoff_us = self._time_us(cutoff)
        group_state = self._groups[group_id]
        assert group_state is not None
        if group_state is _INLINE_TEMPORAL_GROUP:
            handle = self._inline_handles[group_id]
            if self._track_lookup_candidates:
                self._lookup_candidates_inspected += 1
            if handle >= 0 and self._current_times_us[handle] <= cutoff_us:
                yield handle
            return
        assert isinstance(group_state, _SegmentedTemporalGroup)
        final_block = min(
            len(group_state.blocks),
            bisect_right(group_state.block_last_times_us, cutoff_us) + 1,
        )
        yielded = 0
        is_current = self._tracked_is_current if self._track_lookup_candidates else self._is_current
        for block_index in range(final_block):
            block = group_state.blocks[block_index]
            stop = bisect_right(block.times_us, cutoff_us)
            for index in range(stop):
                if not is_current(group_id, block, index):
                    continue
                yield block.handles[index]
                yielded += 1
                if limit is not None and yielded >= limit:
                    return

    def latest_at_or_before(self, group: G, cutoff: datetime) -> int | None:
        """Return the latest current handle at or before a canonical cutoff.

        The packed block boundary and in-block timestamp searches are both
        logarithmic. Current lifecycle starts are immutable, so the common
        predecessor path inspects one record regardless of retained reuse
        history. Version-stale replacement records are skipped defensively.
        """

        group_id = self._group_ids.get(group)
        if group_id is None:
            return None
        cutoff_us = self._time_us(cutoff)
        group_state = self._groups[group_id]
        assert group_state is not None
        if group_state is _INLINE_TEMPORAL_GROUP:
            handle = self._inline_handles[group_id]
            if self._track_lookup_candidates:
                self._lookup_candidates_inspected += 1
            if handle >= 0 and self._current_times_us[handle] <= cutoff_us:
                return handle
            return None

        assert isinstance(group_state, _SegmentedTemporalGroup)
        block_index = min(
            len(group_state.blocks) - 1,
            bisect_right(group_state.block_last_times_us, cutoff_us),
        )
        is_current = self._tracked_is_current if self._track_lookup_candidates else self._is_current
        for current_block_index in range(block_index, -1, -1):
            block = group_state.blocks[current_block_index]
            stop = bisect_right(block.times_us, cutoff_us)
            for position in range(stop - 1, -1, -1):
                if is_current(group_id, block, position):
                    return block.handles[position]
        return None

    def pop_before(
        self,
        group: G,
        cutoff: datetime,
        *,
        limit: int = 4_096,
        inclusive: bool = False,
    ) -> tuple[int, ...]:
        """Remove one bounded physical prefix and return its current handles.

        ``limit`` bounds inspected backing records, including stale versions,
        so repeated watermark calls stream a large sealed prefix without
        rescanning it or rebuilding the remaining group.
        """

        if limit < 0:
            raise ValueError("SegmentedTemporalIndex limit must be non-negative")
        group_id = self._group_ids.get(group)
        if group_id is None or limit == 0:
            return ()
        cutoff_us = self._time_us(cutoff)
        group_state = self._groups[group_id]
        assert group_state is not None
        if group_state is _INLINE_TEMPORAL_GROUP:
            handle = self._inline_handles[group_id]
            if handle < 0:
                return ()
            event_time_us = self._current_times_us[handle]
            due = event_time_us <= cutoff_us if inclusive else event_time_us < cutoff_us
            if not due:
                return ()
            self._active[handle] = 0
            self._live_count -= 1
            self._release_group(group_id)
            return (handle,)

        assert isinstance(group_state, _SegmentedTemporalGroup)
        old_backing = group_state.backing_count
        inspected = 0
        stale_removed = 0
        full_blocks = 0
        partial_prefix = 0
        removed: list[int] = []
        for block in group_state.blocks:
            due_stop = (
                bisect_right(block.times_us, cutoff_us)
                if inclusive
                else bisect_left(block.times_us, cutoff_us)
            )
            consume = min(due_stop, limit - inspected)
            if consume <= 0:
                break
            for position in range(consume):
                inspected += 1
                if not self._is_current(group_id, block, position):
                    stale_removed += 1
                    continue
                handle = block.handles[position]
                self._active[handle] = 0
                self._live_count -= 1
                group_state.live_count -= 1
                removed.append(handle)
            if consume == len(block):
                full_blocks += 1
            else:
                partial_prefix = consume
                break
            if inspected >= limit:
                break

        if inspected == 0:
            return ()
        if full_blocks:
            del group_state.blocks[:full_blocks]
            del group_state.block_last_times_us[:full_blocks]
            del group_state.block_last_sequences[:full_blocks]
        if partial_prefix:
            block = group_state.blocks[0]
            group_state.blocks[0] = block.slice(partial_prefix)
            group_state.block_last_times_us[0] = group_state.blocks[0].times_us[-1]
            group_state.block_last_sequences[0] = group_state.blocks[0].sequences[-1]
        group_state.backing_count -= inspected
        group_state.stale_count -= stale_removed
        self._adjust_group_backing(old_backing, group_state.backing_count)
        if group_state.live_count == 0:
            self._release_group(group_id)
        return tuple(removed)

    def compact(self, *, max_groups: int | None = None) -> int:
        """Inspect and compact a bounded number of groups at a watermark.

        ``max_groups`` limits groups inspected, including groups that do not
        currently need rebuilding. Successive calls resume from a rotating
        cursor so a late group cannot force a scan through every earlier group.
        """
        if max_groups is not None and max_groups < 0:
            raise ValueError("SegmentedTemporalIndex max_groups must be non-negative")
        group_count = len(self._groups)
        if group_count == 0 or max_groups == 0:
            return 0
        started = perf_counter()
        inspected_groups = group_count if max_groups is None else min(max_groups, group_count)
        start_group = self._compaction_cursor % group_count
        compacted_groups = 0
        compaction_work = 0
        for offset in range(inspected_groups):
            group_id = (start_group + offset) % group_count
            group = self._groups[group_id]
            if group is None or group is _INLINE_TEMPORAL_GROUP:
                continue
            assert isinstance(group, _SegmentedTemporalGroup)
            backing = group.backing_count
            if group.stale_count == 0:
                continue
            if group.stale_count < 1_024 and group.stale_count * 4 < backing:
                continue
            compaction_work += backing
            self._rebuild_group(group_id, cutoff_us=None)
            compacted_groups += 1
        self._compaction_cursor = (start_group + inspected_groups) % group_count
        self._compaction_work += compaction_work
        self._compaction_seconds += perf_counter() - started
        return compacted_groups

    def discard_before(
        self,
        cutoff: datetime,
        *,
        max_groups: int | None = None,
    ) -> int:
        """Discard sealed history in an optionally bounded group batch."""
        if max_groups is not None and max_groups < 0:
            raise ValueError("SegmentedTemporalIndex max_groups must be non-negative")
        group_count = len(self._groups)
        if group_count == 0 or max_groups == 0:
            return 0
        started = perf_counter()
        cutoff_us = self._time_us(cutoff)
        removed = 0
        compaction_work = 0
        inspected_groups = group_count if max_groups is None else min(max_groups, group_count)
        start_group = self._discard_cursor % group_count
        for offset in range(inspected_groups):
            group_id = (start_group + offset) % group_count
            group = self._groups[group_id]
            if group is None:
                continue
            if group is _INLINE_TEMPORAL_GROUP:
                compaction_work += 1
                handle = self._inline_handles[group_id]
                if handle >= 0 and self._current_times_us[handle] < cutoff_us:
                    self._active[handle] = 0
                    self._live_count -= 1
                    removed += 1
                    self._release_group(group_id)
                continue
            assert isinstance(group, _SegmentedTemporalGroup)
            compaction_work += group.backing_count
            removed += sum(bisect_left(block.times_us, cutoff_us) for block in group.blocks)
            self._rebuild_group(group_id, cutoff_us=cutoff_us)
        self._discard_cursor = (start_group + inspected_groups) % group_count
        self._compaction_work += compaction_work
        self._compaction_seconds += perf_counter() - started
        return removed

    def _rebuild_group(self, group_id: int, *, cutoff_us: int | None) -> None:
        group = self._groups[group_id]
        if group is None or group is _INLINE_TEMPORAL_GROUP:
            return
        assert isinstance(group, _SegmentedTemporalGroup)
        prior_backing = group.backing_count
        rebuilt = _SegmentedTemporalGroup()
        for block in group.blocks:
            start = 0 if cutoff_us is None else bisect_left(block.times_us, cutoff_us)
            for position in range(start, len(block)):
                if not self._is_current(group_id, block, position):
                    continue
                handle = block.handles[position]
                self._insert_record(
                    rebuilt,
                    block.times_us[position],
                    block.sequences[position],
                    block.versions[position],
                    handle,
                )
                rebuilt.live_count += 1
            if cutoff_us is not None:
                for position in range(0, start):
                    if not self._is_current(group_id, block, position):
                        continue
                    handle = block.handles[position]
                    self._active[handle] = 0
                    self._live_count -= 1
        self._adjust_group_backing(prior_backing, rebuilt.backing_count)
        if rebuilt.live_count == 0:
            self._groups[group_id] = rebuilt
            self._release_group(group_id)
            return
        if rebuilt.live_count == 1:
            handle = rebuilt.blocks[0].handles[0]
            self._groups[group_id] = _INLINE_TEMPORAL_GROUP
            self._inline_handles[group_id] = handle
            return
        self._groups[group_id] = rebuilt

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return live and packed backing temporal cardinality."""
        backing = self._backing_count
        estimated_bytes = 0
        if estimate_bytes:
            estimated_bytes = sum(
                sys.getsizeof(value)
                for value in (
                    self,
                    self._groups,
                    self._group_ids,
                    self._group_keys,
                    self._free_group_ids,
                    self._inline_handles,
                    self._bucket_size_counts,
                    self._current_groups,
                    self._current_times_us,
                    self._current_sequences,
                    self._current_versions,
                    self._active,
                )
            )
            for group in self._groups:
                if group is None or group is _INLINE_TEMPORAL_GROUP:
                    continue
                assert isinstance(group, _SegmentedTemporalGroup)
                estimated_bytes += sum(
                    sys.getsizeof(value)
                    for value in (
                        group,
                        group.blocks,
                        group.block_last_times_us,
                        group.block_last_sequences,
                    )
                )
                estimated_bytes += sum(
                    sys.getsizeof(value)
                    for block in group.blocks
                    for value in (
                        block,
                        block.times_us,
                        block.sequences,
                        block.versions,
                        block.handles,
                    )
                )
        return IndexMetrics(
            live_entries=self._live_count,
            backing_entries=backing,
            stale_entries=max(0, backing - self._live_count),
            allocated_slots=len(self._active),
            secondary_buckets=len(self._group_ids),
            max_bucket_size=self._max_bucket_size,
            high_water_mark=self._high_water_mark,
            lookup_candidates_inspected=self._lookup_candidates_inspected,
            compaction_work=self._compaction_work,
            compaction_seconds=self._compaction_seconds,
            estimated_bytes=estimated_bytes,
        )


@dataclass(frozen=True, slots=True)
class _ReferenceLeaseRecord(Generic[K, OwnerT]):
    """One compact exact lease pair used by both equality indexes."""

    key: K
    owner: OwnerT


class ReferenceLeaseIndex(Generic[K, OwnerT]):
    """Explicit owner/deadline leases for retained canonical identities."""

    def __init__(self) -> None:
        """Create an empty lease index."""
        self._leases: CompactIndexedStore[tuple[K, OwnerT], _ReferenceLeaseRecord[K, OwnerT]] = (
            CompactIndexedStore(
                key=lambda item: item.key,
                owner=lambda item: item.owner,
            )
        )
        self._expirations: ExpiringIndex[tuple[K, OwnerT], bool] = ExpiringIndex()
        self._leased_key_count = 0

    def __len__(self) -> int:
        return len(self._expirations)

    @property
    def leased_key_count(self) -> int:
        """Return the number of distinct retained canonical keys."""

        return self._leased_key_count

    def acquire(self, key: K, owner: OwnerT, *, deadline: float) -> None:
        """Acquire or extend one explicit owner lease."""
        if not math.isfinite(deadline):
            raise ValueError("ReferenceLeaseIndex deadline must be finite")
        pair = (key, owner)
        if pair not in self._leases:
            if self._leases.count("key", key) == 0:
                self._leased_key_count += 1
            self._leases[pair] = _ReferenceLeaseRecord(key=key, owner=owner)
        self._expirations.set(pair, True, deadline)

    def release(self, key: K, owner: OwnerT) -> bool:
        """Release an exact owner lease without scanning other keys."""
        if self._expirations.pop((key, owner)) is None:
            return False
        self._drop_pair(key, owner)
        return True

    def _drop_pair(self, key: K, owner: OwnerT) -> None:
        pair = (key, owner)
        if pair not in self._leases:
            return
        final_key_lease = self._leases.count("key", key) == 1
        self._leases.pop(pair)
        if final_key_lease:
            self._leased_key_count -= 1

    def is_leased(self, key: K) -> bool:
        """Return whether any owner retains a key."""

        return self._leases.count("key", key) > 0

    def owners(self, key: K) -> Iterator[OwnerT]:
        """Yield current owners without copying the owner bucket."""

        for lease in self._leases.find_iter("key", key):
            yield lease.owner

    def keys_for_owner(self, owner: OwnerT) -> Iterator[K]:
        """Yield keys retained by one owner."""

        for lease in self._leases.find_iter("owner", owner):
            yield lease.key

    def release_owner(self, owner: OwnerT) -> tuple[K, ...]:
        """Release every key held by one exact owner."""

        keys = tuple(self.keys_for_owner(owner))
        for key in keys:
            self.release(key, owner)
        return keys

    def expire_before(
        self,
        cutoff: float,
        *,
        inclusive: bool = False,
    ) -> tuple[tuple[K, OwnerT], ...]:
        """Expire due leases and synchronize both equality indexes."""
        expired = self._expirations.expire_before(cutoff, inclusive=inclusive)
        pairs: list[tuple[K, OwnerT]] = []
        for pair, _marker in expired:
            key, owner = pair
            self._drop_pair(key, owner)
            pairs.append(pair)
        return tuple(pairs)

    def compact(
        self,
        *,
        max_primary_slots: int = 4_096,
        max_expiry_entries: int = 4_096,
        force_primary: bool = False,
    ) -> int:
        """Run bounded primary-map and expiry-heap watermark maintenance."""

        primary_work = self._leases.compact_primary(
            max_slots=max_primary_slots,
            force=force_primary,
        )
        expiry_work = self._expirations.compact(max_entries=max_expiry_entries)
        return primary_work + expiry_work

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        """Return lease and expiry backing cardinality."""

        primary = self._leases.metrics(estimate_bytes=estimate_bytes)
        expiry = self._expirations.metrics(estimate_bytes=estimate_bytes)
        return IndexMetrics(
            live_entries=len(self),
            backing_entries=expiry.backing_entries,
            stale_entries=expiry.stale_entries,
            allocated_slots=primary.allocated_slots,
            secondary_buckets=primary.secondary_buckets,
            max_bucket_size=primary.max_bucket_size,
            high_water_mark=max(primary.high_water_mark, expiry.high_water_mark),
            compaction_work=expiry.compaction_work,
            compaction_seconds=expiry.compaction_seconds,
            compaction_pending=(expiry.compaction_pending or primary.primary_compaction_pending),
            estimated_bytes=primary.estimated_bytes + expiry.estimated_bytes,
            primary_map_entries=primary.primary_map_entries,
            primary_map_backing_bytes=primary.primary_map_backing_bytes,
            primary_compaction_pending=primary.primary_compaction_pending,
            primary_compaction_rotations=primary.primary_compaction_rotations,
            primary_compaction_work=primary.primary_compaction_work,
            primary_compaction_seconds=primary.primary_compaction_seconds,
        )


class TemporalAllocationIndex:
    """Exact temporal allocation queries without whole-history scans."""

    _BLOCK_SIZE = 256

    def __init__(self) -> None:
        """Create an empty allocation index."""
        self._blocks: list[list[tuple[datetime, int, int]]] = []
        self._block_last_times: list[datetime] = []
        self._block_max_values: list[int] = []
        self._block_min_values: list[int] = []
        self._summary_tree_capacity = 1
        self._max_summary_tree: list[float] = [float("-inf")] * 2
        self._min_summary_tree: list[float] = [float("inf")] * 2
        self._minus_invariants: dict[int, list[tuple[float, datetime, int]]] = {}
        self._plus_invariants: dict[int, list[tuple[float, datetime, int]]] = {}
        self._value_counts: dict[int, int] = {}
        self._sequence = 0

    def __len__(self) -> int:
        return sum(len(block) for block in self._blocks)

    def discard_before(self, cutoff: datetime) -> int | None:
        """Discard allocations before ``cutoff`` and return their greatest value.

        Allocation indexes are used only for the engine's open scheduling window.
        Rebuilding at an hourly watermark keeps every hot query independent of total
        scenario duration while preserving any allocations authored ahead of the
        sealed period.
        """
        discarded_max: int | None = None
        retained: list[tuple[datetime, int]] = []
        for block in self._blocks:
            for event_time, _sequence, value in block:
                if event_time < cutoff:
                    discarded_max = value if discarded_max is None else max(discarded_max, value)
                else:
                    retained.append((event_time, value))

        self._blocks = []
        self._block_last_times = []
        self._block_max_values = []
        self._block_min_values = []
        self._summary_tree_capacity = 1
        self._max_summary_tree = [float("-inf")] * 2
        self._min_summary_tree = [float("inf")] * 2
        self._minus_invariants = {}
        self._plus_invariants = {}
        self._value_counts = {}
        self._sequence = 0
        for event_time, value in retained:
            self.add(event_time, value)
        return discarded_max

    def add(self, event_time: datetime, value: int) -> None:
        """Record an allocation."""
        record = (event_time, self._sequence, value)
        self._sequence += 1
        block_index = self._block_for_insert(event_time)
        if block_index == len(self._blocks):
            self._blocks.append([record])
            self._block_last_times.append(event_time)
            self._block_max_values.append(value)
            self._block_min_values.append(value)
            self._rebuild_summary_tree()
        else:
            block = self._blocks[block_index]
            position = bisect_right(block, (event_time, math.inf, math.inf))
            block.insert(position, record)
            self._refresh_block_summary(block_index)
            if len(block) > self._BLOCK_SIZE * 2:
                self._split_block(block_index)
            else:
                self._update_summary_tree(block_index)

        epoch = event_time.timestamp()
        minus = value - epoch
        plus = value + epoch
        self._minus_invariants.setdefault(math.floor(minus), []).append((minus, event_time, value))
        self._plus_invariants.setdefault(math.floor(plus), []).append((plus, event_time, value))
        self._value_counts[value] = self._value_counts.get(value, 0) + 1

    def contains_value(self, value: int) -> bool:
        """Return whether an allocation already owns one logical value."""

        return value in self._value_counts

    def max_value_at_or_before(self, event_time: datetime) -> int | None:
        """Return the greatest allocated value at or before an event time."""
        completed_block = bisect_right(self._block_last_times, event_time) - 1
        best = self._range_max(0, completed_block + 1) if completed_block >= 0 else None
        partial_block = completed_block + 1
        if partial_block >= len(self._blocks):
            return best
        for allocated_time, _sequence, value in self._blocks[partial_block]:
            if allocated_time > event_time:
                break
            best = value if best is None else max(best, value)
        return best

    def min_value_after(self, event_time: datetime) -> int | None:
        """Return the least allocated value strictly after an event time."""
        partial_block = bisect_right(self._block_last_times, event_time)
        if partial_block >= len(self._blocks):
            return None
        best: int | None = None
        for allocated_time, _sequence, value in self._blocks[partial_block]:
            if allocated_time > event_time:
                best = value if best is None else min(best, value)
        suffix_min = self._range_min(partial_block + 1, len(self._blocks))
        if suffix_min is not None:
            best = suffix_min if best is None else min(best, suffix_min)
        return best

    def first_record_after(self, event_time: datetime) -> tuple[datetime, int] | None:
        """Return the first allocation record strictly after an event time."""
        first_block = bisect_right(self._block_last_times, event_time)
        for block in self._blocks[first_block : first_block + 1]:
            position = bisect_right(block, (event_time, math.inf, math.inf))
            if position < len(block):
                allocated_time, _sequence, value = block[position]
                return allocated_time, value
        return None

    def matches_elapsed_delta(
        self,
        event_time: datetime,
        candidate: int,
        *,
        tolerance: float,
        integral_seconds: bool = False,
    ) -> bool:
        """Return whether any allocation matches the legacy elapsed-delta predicate."""
        epoch = event_time.timestamp()
        probes = (
            (self._minus_invariants, candidate - epoch),
            (self._plus_invariants, candidate + epoch),
        )
        seen: set[tuple[datetime, int]] = set()
        for buckets, target in probes:
            first_bucket = math.floor(target - tolerance)
            last_bucket = math.floor(target + tolerance)
            for bucket in range(first_bucket, last_bucket + 1):
                for invariant, allocated_time, allocated_value in buckets.get(bucket, ()):
                    if abs(invariant - target) > tolerance:
                        continue
                    record_key = (allocated_time, allocated_value)
                    if record_key in seen:
                        continue
                    seen.add(record_key)
                    elapsed = abs((event_time - allocated_time).total_seconds())
                    if integral_seconds:
                        elapsed = float(int(elapsed))
                    if elapsed < 1.0:
                        continue
                    if abs(abs(candidate - allocated_value) - elapsed) <= tolerance:
                        return True
        return False

    def _block_for_insert(self, event_time: datetime) -> int:
        if not self._blocks:
            return 0
        if event_time >= self._blocks[-1][-1][0]:
            return len(self._blocks) - 1
        return bisect_left(self._block_last_times, event_time)

    def _refresh_block_summary(self, block_index: int) -> None:
        values = [record[2] for record in self._blocks[block_index]]
        self._block_last_times[block_index] = self._blocks[block_index][-1][0]
        self._block_max_values[block_index] = max(values)
        self._block_min_values[block_index] = min(values)

    def _rebuild_summary_tree(self) -> None:
        """Rebuild block summaries after the infrequent block split/append."""
        capacity = 1
        while capacity < len(self._blocks):
            capacity *= 2
        self._summary_tree_capacity = capacity
        self._max_summary_tree = [float("-inf")] * (capacity * 2)
        self._min_summary_tree = [float("inf")] * (capacity * 2)
        for index, (maximum, minimum) in enumerate(
            zip(self._block_max_values, self._block_min_values, strict=True)
        ):
            position = capacity + index
            self._max_summary_tree[position] = maximum
            self._min_summary_tree[position] = minimum
        for position in range(capacity - 1, 0, -1):
            self._max_summary_tree[position] = max(
                self._max_summary_tree[position * 2],
                self._max_summary_tree[(position * 2) + 1],
            )
            self._min_summary_tree[position] = min(
                self._min_summary_tree[position * 2],
                self._min_summary_tree[(position * 2) + 1],
            )

    def _update_summary_tree(self, block_index: int) -> None:
        """Update one block summary in logarithmic time."""
        position = self._summary_tree_capacity + block_index
        self._max_summary_tree[position] = self._block_max_values[block_index]
        self._min_summary_tree[position] = self._block_min_values[block_index]
        position //= 2
        while position:
            self._max_summary_tree[position] = max(
                self._max_summary_tree[position * 2],
                self._max_summary_tree[(position * 2) + 1],
            )
            self._min_summary_tree[position] = min(
                self._min_summary_tree[position * 2],
                self._min_summary_tree[(position * 2) + 1],
            )
            position //= 2

    def _range_max(self, start: int, stop: int) -> int | None:
        """Return a block maximum over ``[start, stop)`` in logarithmic time."""
        if start >= stop:
            return None
        left = start + self._summary_tree_capacity
        right = stop + self._summary_tree_capacity
        result = float("-inf")
        while left < right:
            if left % 2:
                result = max(result, self._max_summary_tree[left])
                left += 1
            if right % 2:
                right -= 1
                result = max(result, self._max_summary_tree[right])
            left //= 2
            right //= 2
        return None if result == float("-inf") else int(result)

    def _range_min(self, start: int, stop: int) -> int | None:
        """Return a block minimum over ``[start, stop)`` in logarithmic time."""
        if start >= stop:
            return None
        left = start + self._summary_tree_capacity
        right = stop + self._summary_tree_capacity
        result = float("inf")
        while left < right:
            if left % 2:
                result = min(result, self._min_summary_tree[left])
                left += 1
            if right % 2:
                right -= 1
                result = min(result, self._min_summary_tree[right])
            left //= 2
            right //= 2
        return None if result == float("inf") else int(result)

    def _split_block(self, block_index: int) -> None:
        block = self._blocks[block_index]
        midpoint = len(block) // 2
        left = block[:midpoint]
        right = block[midpoint:]
        self._blocks[block_index : block_index + 1] = [left, right]
        self._block_last_times[block_index : block_index + 1] = [
            left[-1][0],
            right[-1][0],
        ]
        self._block_max_values[block_index : block_index + 1] = [
            max(record[2] for record in left),
            max(record[2] for record in right),
        ]
        self._block_min_values[block_index : block_index + 1] = [
            min(record[2] for record in left),
            min(record[2] for record in right),
        ]
        self._rebuild_summary_tree()

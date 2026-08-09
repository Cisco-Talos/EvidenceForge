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

import heapq
import math
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Hashable, Iterator, MutableMapping
from datetime import datetime
from typing import Generic, TypeVar

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")
G = TypeVar("G", bound=Hashable)


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
        self._next_order = 0
        self._deadline_extractor = deadline

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

    def set(self, key: K, value: V, deadline: float) -> None:
        """Insert or update a value and its sortable deadline."""
        if key not in self._orders:
            self._orders[key] = self._next_order
            self._next_order += 1
        version = self._versions.get(key, 0) + 1
        self._versions[key] = version
        self._items[key] = value
        self._deadlines[key] = deadline
        heapq.heappush(
            self._heap,
            (deadline, self._orders[key], version, key),
        )

    def pop(self, key: K, default: V | None = None) -> V | None:
        """Remove a key while leaving any stale heap entry harmless."""
        if key not in self._items:
            return default
        value = self._items.pop(key)
        self._deadlines.pop(key, None)
        self._orders.pop(key, None)
        self._versions.pop(key, None)
        return value

    def items(self) -> Iterator[tuple[K, V]]:
        """Iterate live items in primary insertion order."""
        return iter(self._items.items())

    def values(self) -> Iterator[V]:
        """Iterate live values in primary insertion order."""
        return iter(self._items.values())

    def expire_before(
        self,
        cutoff: float,
        *,
        inclusive: bool = False,
    ) -> list[tuple[K, V]]:
        """Remove and return entries whose deadline is before the cutoff."""
        expired: list[tuple[K, V]] = []
        while self._heap:
            deadline, _order, version, key = self._heap[0]
            if deadline > cutoff or (deadline == cutoff and not inclusive):
                break
            heapq.heappop(self._heap)
            if self._versions.get(key) != version or self._deadlines.get(key) != deadline:
                continue
            value = self.pop(key)
            if value is not None:
                expired.append((key, value))
        self._compact_heap_if_needed()
        return expired

    def trim(
        self,
        capacity: int,
        *,
        rank: Callable[[K, V], object],
        reverse: bool = True,
    ) -> list[tuple[K, V]]:
        """Retain the highest-ranked entries using stable insertion ordering."""
        if len(self._items) <= capacity:
            return []
        ranked = sorted(
            self._items.items(),
            key=lambda item: rank(item[0], item[1]),
            reverse=reverse,
        )
        retained = {key for key, _value in ranked[:capacity]}
        removed: list[tuple[K, V]] = []
        for key in tuple(self._items):
            if key in retained:
                continue
            value = self.pop(key)
            if value is not None:
                removed.append((key, value))
        self._compact_heap(force=True)
        return removed

    def trim_earliest(self, capacity: int) -> list[tuple[K, V]]:
        """Evict the earliest-deadline entries in ``O(r log n)`` time.

        Use this for capacity bounds whose retention priority is already the
        expiry deadline. It avoids sorting the entire live index every time a
        high-volume workload crosses its cap.
        """

        if capacity < 0:
            raise ValueError("ExpiringIndex capacity must be non-negative")
        removed: list[tuple[K, V]] = []
        while len(self._items) > capacity and self._heap:
            deadline, _order, version, key = heapq.heappop(self._heap)
            if self._versions.get(key) != version or self._deadlines.get(key) != deadline:
                continue
            value = self.pop(key)
            if value is not None:
                removed.append((key, value))
        self._compact_heap_if_needed()
        return removed

    def _compact_heap_if_needed(self) -> None:
        if len(self._heap) > 100_000 and len(self._heap) > len(self._items) * 4:
            self._compact_heap(force=True)

    def _compact_heap(self, *, force: bool = False) -> None:
        if not force:
            return
        self._heap = [
            (
                deadline,
                self._orders[key],
                self._versions[key],
                key,
            )
            for key, deadline in self._deadlines.items()
        ]
        heapq.heapify(self._heap)


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


class TemporalAllocationIndex:
    """Exact temporal allocation queries without whole-history scans."""

    _BLOCK_SIZE = 256

    def __init__(self) -> None:
        """Create an empty allocation index."""
        self._blocks: list[list[tuple[datetime, int, int]]] = []
        self._block_last_times: list[datetime] = []
        self._block_max_values: list[int] = []
        self._block_min_values: list[int] = []
        self._prefix_max_values: list[int] = []
        self._minus_invariants: dict[int, list[tuple[float, datetime, int]]] = {}
        self._plus_invariants: dict[int, list[tuple[float, datetime, int]]] = {}
        self._sequence = 0

    def __len__(self) -> int:
        return sum(len(block) for block in self._blocks)

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
            prior_max = self._prefix_max_values[-1] if self._prefix_max_values else value
            self._prefix_max_values.append(max(prior_max, value))
        else:
            block = self._blocks[block_index]
            position = bisect_right(block, (event_time, math.inf, math.inf))
            block.insert(position, record)
            self._refresh_block_summary(block_index)
            if len(block) > self._BLOCK_SIZE * 2:
                self._split_block(block_index)
            else:
                self._refresh_prefix_max_values(block_index)

        epoch = event_time.timestamp()
        minus = value - epoch
        plus = value + epoch
        self._minus_invariants.setdefault(math.floor(minus), []).append((minus, event_time, value))
        self._plus_invariants.setdefault(math.floor(plus), []).append((plus, event_time, value))

    def max_value_at_or_before(self, event_time: datetime) -> int | None:
        """Return the greatest allocated value at or before an event time."""
        completed_block = bisect_right(self._block_last_times, event_time) - 1
        best = self._prefix_max_values[completed_block] if completed_block >= 0 else None
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
        best: int | None = None
        for block_index in range(len(self._blocks) - 1, -1, -1):
            block = self._blocks[block_index]
            if block[0][0] > event_time:
                block_min = self._block_min_values[block_index]
                best = block_min if best is None else min(best, block_min)
                continue
            if block[-1][0] <= event_time:
                break
            for allocated_time, _sequence, value in reversed(block):
                if allocated_time <= event_time:
                    break
                best = value if best is None else min(best, value)
            break
        return best

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

    def _refresh_prefix_max_values(self, start: int) -> None:
        """Refresh prefix maxima after a block summary changes."""
        for block_index in range(start, len(self._blocks)):
            prior_max = (
                self._prefix_max_values[block_index - 1]
                if block_index > 0
                else self._block_max_values[block_index]
            )
            self._prefix_max_values[block_index] = max(
                prior_max,
                self._block_max_values[block_index],
            )

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
        prior_prefix = self._prefix_max_values[block_index - 1] if block_index > 0 else None
        left_prefix = self._block_max_values[block_index]
        if prior_prefix is not None:
            left_prefix = max(prior_prefix, left_prefix)
        self._prefix_max_values[block_index : block_index + 1] = [
            left_prefix,
            max(left_prefix, self._block_max_values[block_index + 1]),
        ]
        self._refresh_prefix_max_values(block_index + 2)

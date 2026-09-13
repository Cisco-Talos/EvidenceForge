# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared admission mechanics; registry owners retain synchronization policy."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from threading import Condition, Lock, RLock


class MutationWatermarkGate:
    """Allow disjoint mutations while giving queued watermarks priority.

    A waiting watermark blocks new mutations so already admitted work can
    finish without an endless stream overtaking the barrier. Each registry
    owns a separate instance; checkpoint hydration rebuilds this synchronization
    state instead of serializing it. See test_simplification_gate_characterization.py
    for admission, exception cleanup and independent-instance contracts.
    """

    __slots__ = ("_condition", "_readers", "_waiting_writers", "_writer")

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


@contextmanager
def acquire_stable_locks(entries: list[tuple[tuple[int, int], RLock]]) -> Iterator[None]:
    """Acquire identity-distinct locks in the caller's declared order.

    Keep the first supplied key for a repeated lock. Registries choose their
    participants and ordering keys; this helper only deduplicates, acquires,
    and releases in reverse order. The characterization tests preserve this
    first-key rule and cleanup when the protected operation raises.
    """

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

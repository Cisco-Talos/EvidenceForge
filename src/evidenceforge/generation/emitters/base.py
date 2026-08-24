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

"""Base emitter class for log generation."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from abc import ABC, abstractmethod
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from contextvars import ContextVar, Token, copy_context
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Condition, Event, Lock, Thread, get_ident
from typing import Any
from weakref import ReferenceType, ref

from jinja2.sandbox import SandboxedEnvironment

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.output_targets import OutputTarget, normalize_output_target

logger = logging.getLogger(__name__)
ExactPublicationKey = tuple[str, int, int]
ExactPublicationParticipantKey = tuple[str, int]
_EXACT_ROW_DIGEST_CHUNK_CHARS = 16 * 1024


class ExactPublicationError(RuntimeError):
    """Raised when an exact sink batch loses its owner or lifecycle contract."""


class _ExactPublicationToken:
    """Opaque exact authority token whose namespace never depends on object identity."""

    __slots__ = ("__weakref__", "integrity", "namespace", "ordinal")

    def __init__(self, *, namespace: str, ordinal: int, integrity: str) -> None:
        self.namespace = namespace
        self.ordinal = ordinal
        self.integrity = integrity


@dataclass(slots=True)
class _ExactPublicationAuthorityRecord:
    """Owner-private exact-object locator retained until terminal release or cancel."""

    batch_id: int
    batch_ref: ReferenceType[ExactPublicationBatch]
    token_id: int
    token_ref: ReferenceType[_ExactPublicationToken]
    capacity_reserved: bool = False
    prepared: bool = False
    retained_rows: int = 0
    retained_bytes: int = 0


@dataclass(frozen=True, slots=True)
class ExactPublicationAuthorityCensus:
    """Constant-time active exact-batch authority counts."""

    active_batches: int
    capacity: int
    prepared_batches: int
    retained_rows: int
    retained_bytes: int
    row_capacity: int
    byte_capacity: int
    high_water_batches: int
    high_water_rows: int
    high_water_bytes: int


class ExactPublicationAuthority:
    """Issue bounded stable publication namespaces to one owning dispatcher."""

    def __init__(
        self,
        *,
        capacity: int = 8_192,
        row_capacity: int = 262_144,
        byte_capacity: int = 512 * 1024 * 1024,
    ) -> None:
        if type(capacity) is not int or capacity <= 0:
            raise ValueError("Exact publication authority capacity must be a positive exact int")
        if type(row_capacity) is not int or row_capacity <= 0:
            raise ValueError("Exact publication row capacity must be a positive exact int")
        if type(byte_capacity) is not int or byte_capacity <= 0:
            raise ValueError("Exact publication byte capacity must be a positive exact int")
        self._lock = Lock()
        self._secret = secrets.token_bytes(32)
        self._namespace = secrets.token_hex(16)
        self._capacity = capacity
        self._row_capacity = row_capacity
        self._byte_capacity = byte_capacity
        self._next_ordinal = 1
        self._records: dict[int, _ExactPublicationAuthorityRecord] = {}
        self._prepared_batches = 0
        self._retained_rows = 0
        self._retained_bytes = 0
        self._high_water_batches = 0
        self._high_water_rows = 0
        self._high_water_bytes = 0

    def issue_batch(self) -> ExactPublicationBatch:
        """Issue one exact batch before any canonical owner is allowed to commit."""

        with self._lock:
            if len(self._records) >= self._capacity:
                raise ExactPublicationError("Exact publication batch capacity is exhausted")
            ordinal = self._next_ordinal
            self._next_ordinal += 1
            token = _ExactPublicationToken(
                namespace=self._namespace,
                ordinal=ordinal,
                integrity="",
            )
            token.integrity = self._token_integrity(token)
            batch = ExactPublicationBatch._from_authority(self, token)
            self._records[ordinal] = _ExactPublicationAuthorityRecord(
                batch_id=id(batch),
                batch_ref=ref(batch),
                token_id=id(token),
                token_ref=ref(token),
            )
            self._high_water_batches = max(self._high_water_batches, len(self._records))
            return batch

    def _token_integrity(self, token: _ExactPublicationToken) -> str:
        payload = repr(
            (
                "exact-publication-token-v1",
                token.namespace,
                token.ordinal,
            )
        ).encode("utf-8")
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def _authenticates(
        self,
        batch: ExactPublicationBatch,
        token: _ExactPublicationToken,
    ) -> bool:
        with self._lock:
            record = self._records.get(token.ordinal)
            return bool(
                type(token) is _ExactPublicationToken
                and token.namespace == self._namespace
                and record is not None
                and record.batch_id == id(batch)
                and record.batch_ref() is batch
                and record.token_id == id(token)
                and record.token_ref() is token
                and hmac.compare_digest(token.integrity, self._token_integrity(token))
            )

    def _reserve_prepared(
        self,
        batch: ExactPublicationBatch,
        token: _ExactPublicationToken,
        *,
        retained_rows: int,
        retained_bytes: int,
    ) -> None:
        """Charge one fully frozen batch before its caller may commit canonical state."""

        with self._lock:
            record = self._records.get(token.ordinal)
            if (
                record is None
                or record.batch_id != id(batch)
                or record.batch_ref() is not batch
                or record.token_id != id(token)
                or record.token_ref() is not token
                or record.prepared
            ):
                raise ExactPublicationError("Exact publication preparation lost its authority")
            if record.capacity_reserved:
                if retained_rows > record.retained_rows or retained_bytes > record.retained_bytes:
                    raise ExactPublicationError(
                        "Exact publication preparation exceeds its reserved capacity"
                    )
            else:
                if self._retained_rows + retained_rows > self._row_capacity:
                    raise ExactPublicationError("Exact publication row capacity is exhausted")
                if self._retained_bytes + retained_bytes > self._byte_capacity:
                    raise ExactPublicationError("Exact publication byte capacity is exhausted")
                record.retained_rows = retained_rows
                record.retained_bytes = retained_bytes
                self._retained_rows += retained_rows
                self._retained_bytes += retained_bytes
                self._high_water_rows = max(self._high_water_rows, self._retained_rows)
                self._high_water_bytes = max(self._high_water_bytes, self._retained_bytes)
            record.prepared = True
            if not record.capacity_reserved:
                self._prepared_batches += 1

    def _reserve_capacity(
        self,
        batch: ExactPublicationBatch,
        token: _ExactPublicationToken,
        *,
        row_budget: int,
        byte_budget: int,
    ) -> None:
        """Charge one bounded batch before any caller-owned root may commit."""

        if type(row_budget) is not int or row_budget <= 0:
            raise ExactPublicationError("Exact publication row budget must be a positive exact int")
        if type(byte_budget) is not int or byte_budget <= 0:
            raise ExactPublicationError(
                "Exact publication byte budget must be a positive exact int"
            )
        with self._lock:
            record = self._records.get(token.ordinal)
            if (
                record is None
                or record.batch_id != id(batch)
                or record.batch_ref() is not batch
                or record.token_id != id(token)
                or record.token_ref() is not token
                or record.capacity_reserved
                or record.prepared
            ):
                raise ExactPublicationError("Exact publication capacity lost its authority")
            if self._retained_rows + row_budget > self._row_capacity:
                raise ExactPublicationError("Exact publication row capacity is exhausted")
            if self._retained_bytes + byte_budget > self._byte_capacity:
                raise ExactPublicationError("Exact publication byte capacity is exhausted")
            record.capacity_reserved = True
            record.retained_rows = row_budget
            record.retained_bytes = byte_budget
            self._prepared_batches += 1
            self._retained_rows += row_budget
            self._retained_bytes += byte_budget
            self._high_water_rows = max(self._high_water_rows, self._retained_rows)
            self._high_water_bytes = max(self._high_water_bytes, self._retained_bytes)

    def _rollback_prepared_capacity(
        self,
        batch: ExactPublicationBatch,
        token: _ExactPublicationToken,
    ) -> None:
        """Return one precharged ready batch to its still-reserved capacity shell."""

        with self._lock:
            record = self._records.get(token.ordinal)
            if (
                record is None
                or record.batch_id != id(batch)
                or record.batch_ref() is not batch
                or record.token_id != id(token)
                or record.token_ref() is not token
                or not record.capacity_reserved
                or not record.prepared
            ):
                raise ExactPublicationError(
                    "Exact publication prepared-capacity rollback lost its authority"
                )
            record.prepared = False

    def _release(
        self,
        batch: ExactPublicationBatch,
        token: _ExactPublicationToken,
    ) -> None:
        with self._lock:
            record = self._records.get(token.ordinal)
            if (
                record is None
                or record.batch_id != id(batch)
                or record.batch_ref() is not batch
                or record.token_id != id(token)
                or record.token_ref() is not token
            ):
                raise ExactPublicationError("Exact publication batch lost its issuing authority")
            if record.capacity_reserved or record.prepared:
                self._prepared_batches -= 1
                self._retained_rows -= record.retained_rows
                self._retained_bytes -= record.retained_bytes
            self._records.pop(token.ordinal, None)

    def census(self) -> ExactPublicationAuthorityCensus:
        """Return bounded exact-batch authority counts without scanning sink rows."""

        with self._lock:
            return ExactPublicationAuthorityCensus(
                active_batches=len(self._records),
                capacity=self._capacity,
                prepared_batches=self._prepared_batches,
                retained_rows=self._retained_rows,
                retained_bytes=self._retained_bytes,
                row_capacity=self._row_capacity,
                byte_capacity=self._byte_capacity,
                high_water_batches=self._high_water_batches,
                high_water_rows=self._high_water_rows,
                high_water_bytes=self._high_water_bytes,
            )


@dataclass(frozen=True, slots=True)
class _ExactPublicationRow:
    """One immutable staged sink mutation with exact retry and cleanup callbacks."""

    content_digest: str
    retained_bytes: int
    frozen_content: object
    publish: Callable[[ExactPublicationKey, str, object], None]
    release: Callable[[ExactPublicationKey], None]


@dataclass(frozen=True, slots=True)
class _ExactPublicationParticipant:
    """Pinned exact-participant operations authenticated before registration."""

    owner: object
    register: Callable[[ExactPublicationParticipantKey], None]
    complete: Callable[[ExactPublicationParticipantKey], None]
    abort: Callable[[ExactPublicationParticipantKey], None]


@dataclass(slots=True)
class _ExactPublicationAttempt:
    """One retry-local staging area shared with synchronous emitter workers."""

    batch: ExactPublicationBatch
    staged_rows: list[_ExactPublicationRow] = field(default_factory=list)
    participants: dict[int, object] = field(default_factory=dict)

    def register_participant(self, participant: object) -> None:
        """Fence one final writer/emitter before any exact queue handoff."""

        self.batch._register_participant(participant)
        participant_id = id(participant)
        retained = self.participants.get(participant_id)
        if retained is not None and retained is not participant:
            raise ExactPublicationError("Exact publication participant identity was recycled")
        self.participants[participant_id] = participant


class _ExactPublicationAttemptContext(AbstractContextManager[None]):
    """Install one batch-local retry attempt without leaking it to other dispatches."""

    def __init__(self, attempt: _ExactPublicationAttempt) -> None:
        self._attempt = attempt
        self._token: Token[_ExactPublicationAttempt | None] | None = None

    def __enter__(self) -> None:
        if _EXACT_PUBLICATION_ATTEMPT.get() is not None:
            raise RuntimeError("Exact publication attempts cannot be nested")
        self._token = _EXACT_PUBLICATION_ATTEMPT.set(self._attempt)

    def __exit__(self, *_exc: object) -> None:
        token = self._token
        if token is None:
            raise RuntimeError("Exact publication attempt exited before entry")
        _EXACT_PUBLICATION_ATTEMPT.reset(token)
        self._token = None


class ExactPublicationBatch:
    """Serialize render, durable admission, reconciliation, and terminal release."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Exact publication batches must be issued by ExactPublicationAuthority")

    @classmethod
    def _from_authority(
        cls,
        authority: ExactPublicationAuthority,
        token: _ExactPublicationToken,
    ) -> ExactPublicationBatch:
        batch = object.__new__(cls)
        batch._authority = authority
        batch._token = token
        batch._condition = Condition(Lock())
        batch._state = "issued"
        batch._active_thread = None
        batch._prepared_rows = None
        batch._prepared_result = None
        batch._participants = {}
        batch._commit_cursor = 0
        batch._release_cursor = 0
        batch._retained_bytes = 0
        return batch

    @property
    def _participant_key(self) -> ExactPublicationParticipantKey:
        return (self._token.namespace, self._token.ordinal)

    def _row_key(self, cursor: int) -> ExactPublicationKey:
        return (self._token.namespace, self._token.ordinal, cursor)

    def _require_authority(self) -> None:
        if not self._authority._authenticates(self, self._token):
            raise ExactPublicationError("Exact publication batch is foreign, copied, or stale")

    def _register_participant(self, participant: object) -> None:
        """Pin and register one participant without invoking user code under the batch lock."""

        participant_id = id(participant)
        with self._condition:
            retained = self._participants.get(participant_id)
            if retained is not None:
                if retained.owner is not participant:
                    raise ExactPublicationError(
                        "Exact publication participant identity was recycled"
                    )
                return

        # Attribute access may itself execute arbitrary descriptor code. Resolve and
        # validate every operation before retaining the participant or taking a lock.
        register = getattr(participant, "_register_exact_publication_batch", None)
        if register is None:
            return
        if not callable(register):
            raise ExactPublicationError("Exact publication participant registration is invalid")
        complete = getattr(participant, "_complete_exact_publication_batch", None)
        abort = getattr(participant, "_abort_exact_publication_batch", None)
        if not callable(complete):
            raise ExactPublicationError("Exact publication participant completion is invalid")
        if not callable(abort):
            raise ExactPublicationError("Exact publication participant abort is invalid")
        pinned = _ExactPublicationParticipant(
            owner=participant,
            register=register,
            complete=complete,
            abort=abort,
        )

        with self._condition:
            retained = self._participants.get(participant_id)
            if retained is not None:
                if retained.owner is not participant:
                    raise ExactPublicationError(
                        "Exact publication participant identity was recycled"
                    )
                return
            self._participants[participant_id] = pinned

        # Register last. If it raises after changing the participant, the enclosing
        # operation detaches this pinned record and invokes abort exactly once.
        register(self._participant_key)

    def _has_participant(self, participant: object) -> bool:
        with self._condition:
            retained = self._participants.get(id(participant))
            return retained is not None and retained.owner is participant

    def reserve_participants(self, participants: tuple[object, ...]) -> None:
        """Fence every known final writer/emitter before canonical owner mutation."""

        self._require_authority()
        owner_thread = get_ident()
        with self._condition:
            if self._active_thread is not None or self._state != "issued":
                raise ExactPublicationError(
                    "Exact publication participants must reserve before rendering"
                )
            self._active_thread = owner_thread
        try:
            for participant in participants:
                self._register_participant(participant)
        except BaseException as primary:
            with self._condition:
                detached = self._detach_participants_locked()
                self._state = "issued"
            self._invoke_participants(detached, operation="abort", primary=primary)
            raise
        finally:
            with self._condition:
                if self._active_thread == owner_thread:
                    self._active_thread = None
                self._condition.notify_all()

    def reserve_capacity(self, *, row_budget: int, byte_budget: int) -> None:
        """Reserve exact row and byte capacity before an external root may commit."""

        self._require_authority()
        with self._condition:
            if self._active_thread is not None or self._state != "issued":
                raise ExactPublicationError(
                    "Exact publication capacity must reserve before rendering"
                )
            self._authority._reserve_capacity(
                self,
                self._token,
                row_budget=row_budget,
                byte_budget=byte_budget,
            )

    def _detach_participants_locked(self) -> tuple[_ExactPublicationParticipant, ...]:
        """Detach callbacks exactly once while the caller holds the batch condition."""

        detached = tuple(self._participants.values())
        self._participants.clear()
        return detached

    def _invoke_participants(
        self,
        participants: tuple[_ExactPublicationParticipant, ...],
        *,
        operation: str,
        primary: BaseException | None = None,
    ) -> None:
        """Invoke all detached callbacks once, retaining the first failure as primary."""

        failures: list[BaseException] = []
        for participant in participants:
            callback = participant.complete if operation == "complete" else participant.abort
            try:
                callback(self._participant_key)
            except BaseException as error:
                failures.append(error)
        if not failures:
            return
        if primary is not None:
            for failure in failures:
                primary.add_note(f"Exact participant {operation} cleanup also failed: {failure!r}")
            return
        first, *additional = failures
        for failure in additional:
            first.add_note(f"Additional exact participant {operation} failure: {failure!r}")
        raise first

    @staticmethod
    def _exact_row_digest_and_size(content: object) -> tuple[str, int]:
        """Digest one inert final row with bounded temporary encoding storage."""

        if type(content) is not str:
            raise ExactPublicationError("Exact publication row content must be one exact str")
        digest = hashlib.sha256()
        encoded_size = 0
        for offset in range(0, len(content), _EXACT_ROW_DIGEST_CHUNK_CHARS):
            encoded = content[offset : offset + _EXACT_ROW_DIGEST_CHUNK_CHARS].encode("utf-8")
            encoded_size += len(encoded)
            digest.update(encoded)
        return digest.hexdigest(), encoded_size

    @staticmethod
    def _content_digest(content: object) -> str:
        return ExactPublicationBatch._exact_row_digest_and_size(content)[0]

    @staticmethod
    def _retained_content_bytes(content: object) -> int:
        payload = content if isinstance(content, bytes) else repr(content).encode("utf-8")
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        return len(payload)

    def prepare(self, render: Callable[[], object]) -> object:
        """Render and freeze every row while reserving bounded capacity, without sink writes."""

        self._require_authority()
        owner_thread = get_ident()
        ready_result: object = None
        already_ready = False
        with self._condition:
            if self._active_thread is not None:
                raise ExactPublicationError("Exact publication batch is already active")
            if self._state == "ready":
                self._active_thread = owner_thread
                ready_result = self._prepared_result
                already_ready = True
            elif self._state != "issued":
                raise ExactPublicationError(
                    "Exact publication batch cannot prepare in its current state"
                )
            else:
                self._active_thread = owner_thread
                self._state = "preparing"
        try:
            if already_ready:
                return deepcopy(ready_result)
            attempt = _ExactPublicationAttempt(self)
            with _ExactPublicationAttemptContext(attempt):
                result = render()
            prepared_rows = tuple(attempt.staged_rows)
            prepared_result = deepcopy(result)
            retained_bytes = self._retained_content_bytes(prepared_result) + sum(
                row.retained_bytes for row in prepared_rows
            )
            retained_bytes += 256 * (1 + len(prepared_rows) + len(self._participants))
            self._authority._reserve_prepared(
                self,
                self._token,
                retained_rows=len(prepared_rows),
                retained_bytes=retained_bytes,
            )
            with self._condition:
                if self._state != "preparing" or self._prepared_rows is not None:
                    raise ExactPublicationError(
                        "Exact publication batch changed during preparation"
                    )
                self._prepared_rows = prepared_rows
                self._prepared_result = prepared_result
                self._retained_bytes = retained_bytes
                self._state = "ready"
                ready_result = self._prepared_result
            return deepcopy(ready_result)
        except BaseException as primary:
            detached: tuple[_ExactPublicationParticipant, ...] = ()
            with self._condition:
                if self._prepared_rows is None:
                    detached = self._detach_participants_locked()
                    self._state = "issued"
            self._invoke_participants(detached, operation="abort", primary=primary)
            raise
        finally:
            with self._condition:
                if self._active_thread == owner_thread:
                    self._active_thread = None
                self._condition.notify_all()

    def commit(self) -> object:
        """Resume durable sink admission from the first unacknowledged frozen row."""

        self._require_authority()
        owner_thread = get_ident()
        committed_result: object = None
        already_committed = False
        with self._condition:
            if self._state == "committed":
                committed_result = self._prepared_result
                already_committed = True
            elif self._active_thread is not None:
                raise ExactPublicationError("Exact publication batch is already active")
            elif self._state != "ready":
                raise ExactPublicationError(
                    "Exact publication batch must prepare before durable admission"
                )
            else:
                prepared_rows = self._prepared_rows
                if prepared_rows is None:
                    raise ExactPublicationError("Exact publication batch lost its frozen rows")
                self._active_thread = owner_thread
                self._state = "committing"
        if already_committed:
            return deepcopy(committed_result)
        try:
            while True:
                detached: tuple[_ExactPublicationParticipant, ...] = ()
                terminal = False
                with self._condition:
                    cursor = self._commit_cursor
                    if cursor >= len(prepared_rows):
                        self._state = "committed"
                        detached = self._detach_participants_locked()
                        committed_result = self._prepared_result
                        terminal = True
                    else:
                        row = prepared_rows[cursor]
                if terminal:
                    try:
                        result = deepcopy(committed_result)
                    except BaseException as primary:
                        self._invoke_participants(
                            detached,
                            operation="complete",
                            primary=primary,
                        )
                        raise
                    self._invoke_participants(detached, operation="complete")
                    return result
                if self._content_digest(row.frozen_content) != row.content_digest:
                    raise ExactPublicationError(
                        "Exact publication frozen payload changed before admission"
                    )
                row.publish(
                    self._row_key(cursor),
                    row.content_digest,
                    deepcopy(row.frozen_content),
                )
                with self._condition:
                    if self._commit_cursor != cursor:
                        raise ExactPublicationError("Exact publication cursor changed concurrently")
                    self._commit_cursor += 1
        except BaseException:
            with self._condition:
                if self._state != "committed":
                    self._state = "ready"
            raise
        finally:
            with self._condition:
                if self._active_thread == owner_thread:
                    self._active_thread = None
                self._condition.notify_all()

    def publish(self, render: Callable[[], object]) -> object:
        """Prepare once, then commit or resume exact durable sink admission."""

        with self._condition:
            state = self._state
        if state == "issued":
            self.prepare(render)
        return self.commit()

    def release_no_fail(self) -> None:
        """Release sink receipts only after the dispatcher reaches terminal ownership."""

        owner_thread = get_ident()
        retired_rows: tuple[_ExactPublicationRow, ...] | None = None
        retired_result: object = None
        retired_participants: dict[int, _ExactPublicationParticipant] | None = None
        with self._condition:
            if self._state == "released":
                return
            self._require_authority()
            if self._active_thread is not None:
                raise ExactPublicationError("Exact publication batch is already active")
            if self._state not in {"committed", "releasing"}:
                raise ExactPublicationError(
                    "Exact publication batch cannot release before durable admission"
                )
            self._active_thread = owner_thread
            self._state = "releasing"
        try:
            while True:
                terminal = False
                with self._condition:
                    rows = self._prepared_rows or ()
                    if self._commit_cursor != len(rows):
                        raise ExactPublicationError(
                            "Exact publication batch lost committed row progress"
                        )
                    cursor = self._release_cursor
                    if cursor >= len(rows):
                        self._authority._release(self, self._token)
                        retired_rows = self._prepared_rows
                        retired_result = self._prepared_result
                        retired_participants = self._participants
                        self._prepared_rows = ()
                        self._prepared_result = None
                        self._participants = {}
                        self._retained_bytes = 0
                        self._state = "released"
                        terminal = True
                    else:
                        row = rows[cursor]
                if terminal:
                    del retired_rows, retired_result, retired_participants
                    return
                row.release(self._row_key(cursor))
                with self._condition:
                    if self._release_cursor != cursor:
                        raise ExactPublicationError(
                            "Exact publication release cursor changed concurrently"
                        )
                    self._release_cursor += 1
        finally:
            with self._condition:
                if self._active_thread == owner_thread:
                    self._active_thread = None
                self._condition.notify_all()

    def cancel(self) -> None:
        """Cancel one never-committed batch before any canonical owner commits."""

        retired_rows: tuple[_ExactPublicationRow, ...] | None
        retired_result: object
        with self._condition:
            if self._state == "canceled":
                return
            self._require_authority()
            if (
                self._active_thread is not None
                or self._state not in {"issued", "ready"}
                or self._commit_cursor != 0
            ):
                raise ExactPublicationError(
                    "Only an inactive uncommitted exact publication batch may be canceled"
                )
            self._authority._release(self, self._token)
            retired_rows = self._prepared_rows
            retired_result = self._prepared_result
            self._prepared_rows = ()
            self._prepared_result = None
            detached = self._detach_participants_locked()
            self._retained_bytes = 0
            self._state = "canceled"
        try:
            self._invoke_participants(detached, operation="abort")
        finally:
            del retired_rows, retired_result, detached

    def rollback_ready_to_reserved_capacity(self) -> None:
        """Discard frozen rows while retaining the exact pre-root capacity and writers."""

        retired_rows: tuple[_ExactPublicationRow, ...] | None
        retired_result: object
        with self._condition:
            self._require_authority()
            if (
                self._active_thread is not None
                or self._state != "ready"
                or self._commit_cursor != 0
            ):
                raise ExactPublicationError(
                    "Only an inactive uncommitted ready batch may roll back to reserved capacity"
                )
            self._authority._rollback_prepared_capacity(self, self._token)
            retired_rows = self._prepared_rows
            retired_result = self._prepared_result
            self._prepared_rows = None
            self._prepared_result = None
            self._retained_bytes = 0
            self._state = "issued"
        del retired_rows, retired_result

    @property
    def state(self) -> str:
        """Return detached batch lifecycle state."""

        with self._condition:
            return self._state

    @property
    def commit_cursor(self) -> int:
        """Return the exact count of durably acknowledged ordered rows."""

        with self._condition:
            return self._commit_cursor

    @property
    def prepared_row_count(self) -> int:
        """Return the exact frozen row cardinality after successful preparation."""

        with self._condition:
            rows = self._prepared_rows
            return len(rows) if rows is not None else 0

    def _prepared_row_facts(self) -> tuple[tuple[str, str, int], ...]:
        """Return callback-free content facts for exact ready-row authentication."""

        self._require_authority()
        with self._condition:
            if self._state != "ready" or self._prepared_rows is None:
                raise ExactPublicationError(
                    "Exact prepared-row facts require one ready publication batch"
                )
            facts: list[tuple[str, str, int]] = []
            for row in self._prepared_rows:
                if (
                    type(row) is not _ExactPublicationRow
                    or type(row.frozen_content) is not str
                    or type(row.content_digest) is not str
                    or len(row.content_digest) != 64
                    or any(character not in "0123456789abcdef" for character in row.content_digest)
                    or type(row.retained_bytes) is not int
                    or row.retained_bytes <= 0
                ):
                    raise ExactPublicationError("Exact prepared-row facts are malformed")
                expected_digest, expected_bytes = self._exact_row_digest_and_size(
                    row.frozen_content
                )
                if row.content_digest != expected_digest or row.retained_bytes != expected_bytes:
                    raise ExactPublicationError(
                        "Exact prepared-row content changed after reservation"
                    )
                facts.append(
                    (
                        row.frozen_content,
                        row.content_digest,
                        row.retained_bytes,
                    )
                )
            return tuple(facts)

    @property
    def released(self) -> bool:
        """Return whether every retained sink receipt and payload was released."""

        with self._condition:
            return self._state == "released"


_EXACT_PUBLICATION_ATTEMPT: ContextVar[_ExactPublicationAttempt | None] = ContextVar(
    "evidenceforge_exact_publication_attempt",
    default=None,
)
_EXACT_PREFIX_BARRIER_EMITTER: ContextVar[int | None] = ContextVar(
    "evidenceforge_exact_prefix_barrier_emitter",
    default=None,
)
_QUEUE_PUT = Queue.put


def fsync_directory(path: Path) -> None:
    """Durably publish a newly created or atomically replaced directory entry."""

    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def stage_exact_publication_row(
    sink: object,
    content: object,
    *,
    publish: Callable[[ExactPublicationKey, str, object], None],
    release: Callable[[ExactPublicationKey], None],
) -> bool:
    """Stage one immutable sink row when an exact dispatcher batch is active."""

    attempt = _EXACT_PUBLICATION_ATTEMPT.get()
    if attempt is None:
        return False
    content_digest, retained_bytes = ExactPublicationBatch._exact_row_digest_and_size(content)
    attempt.register_participant(sink)
    reserve = getattr(sink, "_reserve_exact_publication_row", None)
    if reserve is not None:
        if not callable(reserve):
            raise ExactPublicationError("Exact publication sink row reservation is invalid")
        reserve(
            attempt.batch._row_key(len(attempt.staged_rows)),
            content_digest,
            retained_bytes,
        )
    attempt.staged_rows.append(
        _ExactPublicationRow(
            content_digest=content_digest,
            retained_bytes=retained_bytes,
            frozen_content=content,
            publish=publish,
            release=release,
        )
    )
    return True


def exact_publication_attempt_active() -> bool:
    """Return whether the current context is freezing one exact publication batch."""

    return _EXACT_PUBLICATION_ATTEMPT.get() is not None


def exact_publication_staged_row_count() -> int:
    """Return the current exact-preflight row count for target provenance checks."""

    attempt = _EXACT_PUBLICATION_ATTEMPT.get()
    if attempt is None:
        raise ExactPublicationError(
            "Exact staged-row count requires an active publication preflight"
        )
    return len(attempt.staged_rows)


def exact_publication_staged_row_contents(
    row_start: int,
    row_end: int,
) -> tuple[str, ...]:
    """Return one bounded frozen-row slice during exact provenance preflight."""

    attempt = _EXACT_PUBLICATION_ATTEMPT.get()
    if attempt is None:
        raise ExactPublicationError(
            "Exact staged-row inspection requires an active publication preflight"
        )
    if (
        type(row_start) is not int
        or type(row_end) is not int
        or row_start < 0
        or row_end < row_start
        or row_end > len(attempt.staged_rows)
    ):
        raise ExactPublicationError("Exact staged-row inspection range is invalid")
    return tuple(row.frozen_content for row in attempt.staged_rows[row_start:row_end])


def exact_publication_staged_row_facts(
    row_start: int,
    row_end: int,
) -> tuple[tuple[str, str, int], ...]:
    """Return actual inert content, digest, and byte count for one staged slice.

    This inspection API is deliberately available only inside the active exact
    preflight.  It lets a closed source adapter bind semantic ordering proofs to
    the same immutable bytes that the batch will later commit, without exposing
    participant callbacks or mutable row objects.
    """

    attempt = _EXACT_PUBLICATION_ATTEMPT.get()
    if attempt is None:
        raise ExactPublicationError(
            "Exact staged-row facts require an active publication preflight"
        )
    if (
        type(row_start) is not int
        or type(row_end) is not int
        or row_start < 0
        or row_end < row_start
        or row_end > len(attempt.staged_rows)
    ):
        raise ExactPublicationError("Exact staged-row facts range is invalid")
    facts: list[tuple[str, str, int]] = []
    for row in attempt.staged_rows[row_start:row_end]:
        if (
            type(row.frozen_content) is not str
            or type(row.content_digest) is not str
            or len(row.content_digest) != 64
            or any(character not in "0123456789abcdef" for character in row.content_digest)
            or type(row.retained_bytes) is not int
            or row.retained_bytes <= 0
        ):
            raise ExactPublicationError("Exact staged-row facts are malformed")
        expected_digest, expected_bytes = ExactPublicationBatch._exact_row_digest_and_size(
            row.frozen_content
        )
        if row.content_digest != expected_digest or row.retained_bytes != expected_bytes:
            raise ExactPublicationError("Exact staged-row facts changed after reservation")
        facts.append((row.frozen_content, row.content_digest, row.retained_bytes))
    return tuple(facts)


def register_exact_publication_participant(participant: object) -> bool:
    """Fence one emitter or final writer before an exact render can mutate its sink."""

    attempt = _EXACT_PUBLICATION_ATTEMPT.get()
    if attempt is None:
        return False
    attempt.register_participant(participant)
    return True


class _FlushRequest:
    """FIFO control message requesting an emitter-thread barrier flush."""

    def __init__(self) -> None:
        self.completed = Event()


class _ExactPublicationDrainRequest:
    """FIFO position proving that every pre-fence worker item completed."""

    def __init__(self) -> None:
        self.completed = Event()


@dataclass(slots=True)
class _ExactQueuedPublication:
    """One synchronous exact-publication queue item with a worker acknowledgement."""

    payload: dict[str, Any]
    attempt: _ExactPublicationAttempt
    completed: Event = field(default_factory=Event)
    error: BaseException | None = None


def exact_publication_queue_payload(
    item: object,
) -> tuple[object, _ExactQueuedPublication | None]:
    """Return a worker payload plus its optional exact publication acknowledgement."""

    if type(item) is _ExactQueuedPublication:
        return item.payload, item
    return item, None


def complete_exact_publication_queue_item(
    queued: _ExactQueuedPublication | None,
    error: BaseException | None,
) -> None:
    """Commit or release one exact queued row and wake its producer."""

    if queued is None:
        return
    if error is not None:
        queued.error = error
    queued.completed.set()


def exact_publication_worker_attempt(
    queued: _ExactQueuedPublication | None,
) -> AbstractContextManager[None]:
    """Return the retained row batch context for one worker-side sink mutation."""

    if queued is None:
        return nullcontext()
    return _ExactPublicationAttemptContext(queued.attempt)


class LogEmitter(ABC):
    """Abstract base class for log emitters.

    Emitters write log events to files in specific formats. Each emitter:
    - Buffers events (default 10K) before flushing to disk
    - Uses format definitions to render events
    - Writes to a specific output file

    Phase 2.1 adds optional threaded mode:
    - Events posted to bounded queue (non-blocking)
    - Background thread consumes queue and renders events
    - Hour-level barriers for temporal consistency

    Subclasses must implement:
    - emit_event(): Process and buffer a single event
    - _render_event(): Convert event data to formatted string
    """

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
    ):
        """Initialize emitter.

        Args:
            format_def: Format definition for this log type
            output_path: Path to write log file
            buffer_size: Number of events to buffer before flushing (default: 10K)
            threaded: Enable threaded mode with queue-based processing (Phase 2.1)
        """
        self.format_def = format_def
        self.output_path = output_path
        self.buffer_size = buffer_size
        self.output_target = OutputTarget.DEFAULT
        self.buffer: list[str] = []
        self.event_count = 0
        # DESIGN DECISION: StrictUndefined intentionally removed (commit 5a4e7db).
        # Templates use | default(...) for optional fields that legitimately
        # render as empty. SandboxedEnvironment remains for SSTI protection.
        # Template completeness tests in test_sysmon_new_events.py catch
        # variable name mismatches for required fields.
        self._template_env = SandboxedEnvironment(autoescape=False)
        self._template = self._template_env.from_string(format_def.output.template)
        self._header_written = False
        self._file_lock = Lock()  # Thread-safe file I/O and buffer access
        self._exact_publication_receipts: dict[ExactPublicationKey, str] = {}
        self._exact_file_pending: dict[ExactPublicationKey, tuple[str, int, int]] = {}
        self._exact_publication_condition = Condition(Lock())
        self._active_exact_publication_keys: set[ExactPublicationParticipantKey] = set()
        self._pending_exact_publication_key: ExactPublicationParticipantKey | None = None
        # Close admission, exact fences, and queue handoff share one lock so no
        # successful check can be overtaken by a terminal close transition.
        self._close_condition = self._exact_publication_condition
        self._close_state = "open"
        self._close_thread: int | None = None
        self._queue_admissions = 0
        self._footer_pending: tuple[str, int, int] | None = None
        self._footer_written = False

        # Threading support (Phase 2.1)
        self.threaded = threaded
        self._event_queue: Queue | None = None
        self._stop_event: Event | None = None
        self._thread: Thread | None = None
        self._thread_error: Exception | None = None

        if self.threaded:
            self._event_queue = Queue(maxsize=50000)  # Bounded queue for backpressure
            self._stop_event = Event()
            worker_context = copy_context()
            self._thread = Thread(
                target=worker_context.run,
                args=(self._run,),
                daemon=True,
                name=f"Emitter-{format_def.name}",
            )
            self._thread.start()
            logger.debug(f"Started emitter thread for {format_def.name}")

    def configure_output_target(self, target: str | OutputTarget | None) -> None:
        """Configure the generated-output target for this emitter."""
        self.output_target = normalize_output_target(target)

    @property
    def supports_exact_projection_publication(self) -> bool:
        """Return whether ``emit`` stages every visible row in an exact batch.

        The default is deliberately closed.  Emitter families may opt in only
        when their final writer owns exact reservation, lost-return recovery,
        and release for every row produced by ``emit``.
        """

        return False

    @abstractmethod
    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Emit a single log event.

        In threaded mode, posts to queue. In non-threaded mode, renders immediately.

        Args:
            event_data: Event data dictionary with field values
        """
        pass

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        """Return True if this emitter can render this event type.

        Default: returns False. Subclasses override with _supported_types check.
        During migration, un-migrated emitters return False for all events
        (they still work via the old emit_event() path).
        """
        return False

    def emit(self, event: CanonicalOccurrence) -> None:
        """Render a CanonicalOccurrence to this emitter's format.

        Default: raises NotImplementedError. Subclasses implement per-type
        render methods during Phase 7.2 migration.
        """
        raise NotImplementedError(
            f"{type(self).__name__} has not implemented emit() for {event.event_type}"
        )

    def emit_raw(self, event_data: dict[str, Any]) -> None:
        """Emit from raw dict -- escape hatch for RawProjectionRequest.

        Delegates to existing emit_event() pipeline.
        """
        self.emit_event(event_data)

    @abstractmethod
    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render event data to formatted log string.

        Args:
            event_data: Event data dictionary

        Returns:
            Formatted log entry as string
        """
        pass

    def _run(self) -> None:
        """Thread run loop - consume from queue and render events.

        This method runs in the emitter thread (not main thread).
        Continuously processes events from the queue until stop signal received.
        """
        logger.debug(f"Emitter thread started for {self.format_def.name}")

        while not self._stop_event.is_set():
            try:
                # Try to get event from queue with timeout
                queue_item = self._event_queue.get(timeout=0.1)
                queued: _ExactQueuedPublication | None = None
                try:
                    if self._handle_flush_request(queue_item):
                        continue
                    event_data, queued = exact_publication_queue_payload(queue_item)
                    if not isinstance(event_data, dict):
                        raise TypeError("Emitter queue item must contain an event dictionary")
                    self._wait_for_exact_publication_turn(queued)
                    try:
                        # Render and buffer the event (None means skip)
                        with exact_publication_worker_attempt(queued):
                            rendered = self._render_event(event_data)
                            if rendered is not None:
                                self._buffer_event(rendered)
                    except BaseException as error:
                        complete_exact_publication_queue_item(queued, error)
                        if queued is None:
                            raise
                        continue
                    complete_exact_publication_queue_item(queued, None)
                except Exception as exc:  # noqa: BLE001
                    self._thread_error = exc
                    logger.exception(
                        "Unhandled exception in %s emitter thread; stopping thread",
                        self.format_def.name,
                    )
                    self._stop_event.set()
                finally:
                    # Always mark task done, even if rendering failed.
                    # Otherwise queue join/barrier can deadlock forever.
                    self._event_queue.task_done()

            except Empty:
                continue

        # Final flush before thread exits
        logger.debug(f"Emitter thread stopping for {self.format_def.name}, final flush")
        self.flush()
        logger.debug(f"Emitter thread stopped for {self.format_def.name}")

    def _emit_threaded(self, event_data: dict[str, Any]) -> None:
        """Post event to queue in threaded mode.

        Args:
            event_data: Event data to queue
        """
        attempt = _EXACT_PUBLICATION_ATTEMPT.get()
        if attempt is None:
            self._begin_queue_admission()
            try:
                try:
                    self._event_queue.put(event_data, timeout=1.0)
                except Full:
                    logger.warning(
                        f"Event queue full for {self.format_def.name} emitter, "
                        "applying backpressure"
                    )
                    self._event_queue.put(event_data, block=True)
            finally:
                self._finish_queue_admission()
            return
        attempt.register_participant(self)
        participant_key = attempt.batch._participant_key
        owns_participant = attempt.batch._has_participant(self)
        with self._exact_publication_condition:
            if (
                not owns_participant
                or self._active_exact_publication_keys != {participant_key}
                or self._close_state == "closed"
            ):
                raise ExactPublicationError(
                    f"{self.format_def.name} exact queue handoff lost its participant fence"
                )
        queued = _ExactQueuedPublication(payload=deepcopy(event_data), attempt=attempt)
        while True:
            self._raise_if_thread_failed()
            try:
                _QUEUE_PUT(self._event_queue, queued, block=True, timeout=0.1)
                break
            except Full:
                continue
        while not queued.completed.wait(timeout=0.1):
            self._raise_if_thread_failed()
        if queued.error is not None:
            raise queued.error

    def barrier_flush(self) -> None:
        """Signal flush and wait for completion (hour-level barrier).

        This ensures all queued events are rendered and written to disk
        before proceeding. Used for temporal consistency in Phase 2.1.
        """
        attempt = _EXACT_PUBLICATION_ATTEMPT.get()
        if attempt is not None and attempt.batch._has_participant(self):
            raise ExactPublicationError(
                f"{self.format_def.name} barrier cannot re-enter its active exact render"
            )
        self._begin_queue_admission(allow_closing_owner=True)
        try:
            self._barrier_flush_admitted()
        finally:
            self._finish_queue_admission()

    def _barrier_flush_admitted(self) -> None:
        """Complete one barrier whose caller already owns its admission."""

        if self.threaded:
            logger.debug(f"Waiting for {self.format_def.name} emitter to flush at barrier")
            self._raise_if_thread_failed()

            # A FIFO control message preserves the exact event boundary while
            # waking the worker immediately instead of waiting for Queue.get()
            # to time out before observing a separate Event.
            request = _FlushRequest()
            while True:
                self._raise_if_thread_failed()
                try:
                    self._event_queue.put(request, timeout=0.1)
                    break
                except Full:
                    continue

            while not request.completed.wait(timeout=0.1):
                self._raise_if_thread_failed()
            self._raise_if_thread_failed()

            logger.debug(f"Barrier flush complete for {self.format_def.name}")
        else:
            self._flush_at_barrier()

    def _handle_flush_request(self, queue_item: Any) -> bool:
        """Process a queued barrier request and acknowledge its completion."""
        if type(queue_item) is _ExactPublicationDrainRequest:
            queue_item.completed.set()
            return True
        if not isinstance(queue_item, _FlushRequest):
            return False

        barrier_token = _EXACT_PREFIX_BARRIER_EMITTER.set(id(self))
        try:
            self._wait_for_exact_publication_turn(None)
            logger.debug(f"Flushing {self.format_def.name} emitter at barrier")
            self._flush_at_barrier()
        except Exception as exc:  # noqa: BLE001
            self._thread_error = exc
            logger.exception(
                "Unhandled exception flushing %s emitter thread; stopping thread",
                self.format_def.name,
            )
            self._stop_event.set()
        finally:
            _EXACT_PREFIX_BARRIER_EMITTER.reset(barrier_token)
            queue_item.completed.set()
        return True

    def _flush_at_barrier(self) -> None:
        """Perform this emitter's existing hour-boundary flush behavior."""
        self.flush()

    def stop_thread(self) -> None:
        """Gracefully shutdown emitter thread.

        Signals the thread to stop, waits for it to complete, and performs
        final flush. Call this during shutdown or cleanup.
        """
        self._wait_for_exact_publication_turn(None)
        if self.threaded and self._thread and self._thread.is_alive():
            logger.info(f"Stopping emitter thread for {self.format_def.name}")
            self.barrier_flush()
            self._stop_event.set()
            self._thread.join(timeout=5.0)

            if self._thread.is_alive():
                logger.warning(
                    f"Emitter thread for {self.format_def.name} did not stop within timeout"
                )
            self._raise_if_thread_failed()

    def _require_accepting_events(self) -> None:
        """Reject new public work once shutdown begins, while draining queued worker work."""

        with self._close_condition:
            self._require_accepting_events_locked()

    def _require_accepting_events_locked(self) -> None:
        """Validate admission while the shared close/exact condition is held."""

        worker_thread = self._thread.ident if self._thread is not None else None
        stopped = self._stop_event is not None and self._stop_event.is_set()
        if (
            stopped
            or self._close_state == "closed"
            or (self._close_state == "closing" and get_ident() != worker_thread)
        ):
            raise RuntimeError(f"{self.format_def.name} emitter is closing or closed")

    def _begin_queue_admission(
        self,
        *,
        allow_closing_owner: bool = False,
        allow_exact: bool = False,
    ) -> None:
        """Reserve one FIFO handoff without overtaking an exact registration."""

        attempt = _EXACT_PUBLICATION_ATTEMPT.get()
        if allow_exact and attempt is not None:
            # Synchronous multiplex emitters must install their participant
            # fence before counting the exact render as a queue admission.
            # Otherwise dynamic first registration waits on its own admission.
            attempt.register_participant(self)
        owns_participant = (
            allow_exact and attempt is not None and attempt.batch._has_participant(self)
        )
        allowed = (
            attempt.batch._participant_key if owns_participant and attempt is not None else None
        )
        owner_thread = get_ident()
        worker_thread = self._thread.ident if self._thread is not None else None
        prefix_barrier_worker = (
            owner_thread == worker_thread and _EXACT_PREFIX_BARRIER_EMITTER.get() == id(self)
        )
        with self._close_condition:
            while (
                self._pending_exact_publication_key is not None and not prefix_barrier_worker
            ) or (
                self._active_exact_publication_keys
                and self._active_exact_publication_keys != {allowed}
            ):
                self._close_condition.wait()
            closing_owner = (
                allow_closing_owner
                and self._close_state == "closing"
                and self._close_thread == owner_thread
            )
            active_exact_owner = (
                allowed is not None
                and self._close_state == "closing"
                and self._active_exact_publication_keys == {allowed}
            )
            if closing_owner:
                if self._stop_event is not None and self._stop_event.is_set():
                    raise RuntimeError(f"{self.format_def.name} emitter is stopping or stopped")
            elif not active_exact_owner:
                self._require_accepting_events_locked()
            self._queue_admissions += 1

    def _finish_queue_admission(self) -> None:
        with self._close_condition:
            if self._queue_admissions <= 0:
                raise RuntimeError("Emitter queue admission accounting underflowed")
            self._queue_admissions -= 1
            self._close_condition.notify_all()

    def _begin_close(self) -> bool:
        """Claim the serialized close transition, or return False after terminal close."""

        owner_thread = get_ident()
        with self._close_condition:
            while True:
                while self._close_state == "closing":
                    if self._close_thread == owner_thread:
                        raise RuntimeError("Emitter close cannot be re-entered")
                    self._close_condition.wait()
                if self._close_state == "closed":
                    return False
                if self._pending_exact_publication_key is None:
                    break
                self._close_condition.wait()
            self._close_state = "closing"
            self._close_thread = owner_thread
            while self._active_exact_publication_keys or self._queue_admissions:
                self._close_condition.wait()
            return True

    def _finish_close(self) -> None:
        with self._close_condition:
            if (
                self._pending_exact_publication_key is not None
                or self._active_exact_publication_keys
                or self._queue_admissions
            ):
                raise ExactPublicationError(
                    "Emitter cannot close with unresolved exact rows or queue admissions"
                )
            self._close_state = "closed"
            self._close_thread = None
            self._close_condition.notify_all()

    def _fail_close(self) -> None:
        with self._close_condition:
            self._close_state = "open"
            self._close_thread = None
            self._close_condition.notify_all()

    def _raise_if_thread_failed(self) -> None:
        """Raise RuntimeError if emitter thread died or recorded an exception."""
        if self._thread_error is not None:
            raise RuntimeError(
                f"{self.format_def.name} emitter thread failed"
            ) from self._thread_error
        if self._thread and not self._thread.is_alive() and not self._stop_event.is_set():
            raise RuntimeError(f"{self.format_def.name} emitter thread stopped unexpectedly")

    def _register_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        """Drain the ordinary FIFO prefix, then install one exact participant fence."""

        worker_thread = self._thread.ident if self._thread is not None else None
        if worker_thread == get_ident():
            raise ExactPublicationError(
                f"{self.format_def.name} exact publication cannot register from its worker"
            )
        claimed = False
        try:
            with self._exact_publication_condition:
                if key in self._active_exact_publication_keys:
                    return
                foreign = self._active_exact_publication_keys - {key}
                if foreign or self._pending_exact_publication_key is not None:
                    raise ExactPublicationError(
                        f"{self.format_def.name} already has an unresolved exact publication"
                    )
                if self._close_state != "open":
                    raise ExactPublicationError(
                        f"{self.format_def.name} is closing or closed during exact publication"
                    )
                self._pending_exact_publication_key = key
                claimed = True
                self._exact_publication_condition.notify_all()
                while self._queue_admissions:
                    self._exact_publication_condition.wait(timeout=0.1)
                    if self.threaded:
                        self._raise_if_thread_failed()
            if self.threaded:
                self._drain_threaded_before_exact_publication()
            self._activate_exact_publication_batch(key)
        except BaseException:
            if claimed:
                with self._exact_publication_condition:
                    if self._pending_exact_publication_key == key:
                        self._pending_exact_publication_key = None
                    self._active_exact_publication_keys.discard(key)
                    self._exact_publication_condition.notify_all()
            raise

    def _drain_threaded_before_exact_publication(self) -> None:
        """Acknowledge one FIFO marker after every pre-fence worker item."""

        request = _ExactPublicationDrainRequest()
        while True:
            self._raise_if_thread_failed()
            try:
                _QUEUE_PUT(self._event_queue, request, block=True, timeout=0.1)
                break
            except Full:
                continue
        while not request.completed.wait(timeout=0.1):
            self._raise_if_thread_failed()
        self._raise_if_thread_failed()

    def _activate_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        """Install a participant fence after the owning protocol drains its prefix."""

        with self._exact_publication_condition:
            foreign = self._active_exact_publication_keys - {key}
            pending = self._pending_exact_publication_key
            if foreign or pending not in {None, key}:
                raise ExactPublicationError(
                    f"{self.format_def.name} already has an unresolved exact publication"
                )
            if self._close_state != "open" and key not in self._active_exact_publication_keys:
                raise ExactPublicationError(
                    f"{self.format_def.name} is closing or closed during exact publication"
                )
            self._active_exact_publication_keys.add(key)
            if pending == key:
                self._pending_exact_publication_key = None
            self._exact_publication_condition.notify_all()

    def _complete_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        """Release one exact emitter fence after all staged sink rows commit."""

        with self._exact_publication_condition:
            if self._pending_exact_publication_key == key:
                self._pending_exact_publication_key = None
            self._active_exact_publication_keys.discard(key)
            self._exact_publication_condition.notify_all()

    def _abort_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        """Release one exact emitter fence during explicit precanonical cancel."""

        self._complete_exact_publication_batch(key)

    def _wait_for_exact_publication_turn(
        self,
        queued: _ExactQueuedPublication | None,
    ) -> None:
        """Block unrelated queue/barrier/close work behind exact admission."""

        allowed = queued.attempt.batch._participant_key if queued is not None else None
        worker_thread = self._thread.ident if self._thread is not None else None
        owner_thread = get_ident()
        with self._exact_publication_condition:
            while (
                self._pending_exact_publication_key is not None and owner_thread != worker_thread
            ) or (
                self._active_exact_publication_keys
                and (allowed is None or self._active_exact_publication_keys != {allowed})
            ):
                self._exact_publication_condition.wait()

    def _write_header(self) -> None:
        """Write header to output file if format has one (thread-safe)."""
        with self._file_lock:
            self._write_header_unlocked()

    def _write_header_unlocked(self) -> None:
        """Internal header write (must hold _file_lock).

        Private method called while already holding the lock.
        """
        if self.format_def.output.header_template and not self._header_written:
            header_template = self._template_env.from_string(self.format_def.output.header_template)
            header = header_template.render()

            # Write header to file
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.output_path, "w", encoding=self.format_def.output.encoding) as f:
                f.write(header)
                if not header.endswith("\n"):
                    f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            fsync_directory(self.output_path.parent)

            self._header_written = True

    def _buffer_event(self, rendered: str) -> None:
        """Add rendered event to buffer and flush if needed (thread-safe).

        Args:
            rendered: Rendered event string
        """
        if stage_exact_publication_row(
            self,
            rendered,
            publish=lambda key, digest, frozen: self._commit_exact_buffer_row(
                key,
                digest,
                frozen,
            ),
            release=self._release_exact_buffer_row,
        ):
            return
        self._require_accepting_events()
        owner_thread = get_ident()
        worker_thread = self._thread.ident if self._thread is not None else None
        with self._close_condition:
            while (
                self._pending_exact_publication_key is not None and owner_thread != worker_thread
            ) or self._active_exact_publication_keys:
                self._close_condition.wait()
            self._require_accepting_events_locked()
            with self._file_lock:
                self.buffer.append(rendered)
                self.event_count += 1
                if len(self.buffer) >= self.buffer_size:
                    self._flush_unlocked()

    def _commit_exact_buffer_row(
        self,
        key: ExactPublicationKey,
        digest: str,
        frozen: object,
    ) -> None:
        """Admit one exact row at its final append boundary with file reconciliation."""

        if type(frozen) is not str:
            raise ExactPublicationError("Exact direct-file row must retain one exact str")
        rendered = frozen
        encoded = rendered if rendered.endswith("\n") else f"{rendered}\n"
        payload = encoded.encode(self.format_def.output.encoding)
        participant_key = key[:2]
        with self._exact_publication_condition:
            if participant_key not in self._active_exact_publication_keys:
                raise ExactPublicationError("Exact direct-file admission lost its emitter fence")
            with self._file_lock:
                retained = self._exact_publication_receipts.get(key)
                if retained is not None:
                    if retained != digest:
                        raise ExactPublicationError(
                            "Exact publication row content changed on retry"
                        )
                    return
                self._flush_unlocked()
                if not self._header_written:
                    self._write_header_unlocked()
                    self._header_written = True
                self.output_path.parent.mkdir(parents=True, exist_ok=True)
                pending = self._exact_file_pending.get(key)
                if pending is None:
                    offset = self.output_path.stat().st_size if self.output_path.exists() else 0
                    pending = (digest, offset, len(payload))
                    self._exact_file_pending[key] = pending
                pending_digest, offset, payload_length = pending
                if pending_digest != digest or payload_length != len(payload):
                    raise ExactPublicationError("Exact direct-file admission changed on retry")
                mode = "r+b" if self.output_path.exists() else "w+b"
                with open(self.output_path, mode) as output:
                    output.seek(offset)
                    retained_payload = output.read(payload_length)
                    if retained_payload == payload:
                        output.flush()
                        os.fsync(output.fileno())
                        fsync_directory(self.output_path.parent)
                        self._exact_publication_receipts[key] = digest
                        self.event_count += 1
                        return
                    if retained_payload:
                        if not payload.startswith(retained_payload):
                            raise ExactPublicationError(
                                "Exact direct-file admission found conflicting bytes"
                            )
                        output.seek(0, os.SEEK_END)
                        if output.tell() != offset + len(retained_payload):
                            raise ExactPublicationError(
                                "Exact direct-file partial admission was overtaken"
                            )
                        output.truncate(offset)
                    output.seek(offset)
                    output.write(payload)
                    output.flush()
                    os.fsync(output.fileno())
                    output.seek(offset)
                    if output.read(payload_length) != payload:
                        raise ExactPublicationError(
                            "Exact direct-file admission did not retain its bytes"
                        )
                fsync_directory(self.output_path.parent)
                self._exact_publication_receipts[key] = digest
                self.event_count += 1

    def _stage_exact_publication_mutation(
        self,
        content: object,
        mutation: Callable[[], None],
    ) -> bool:
        """Stage one emitter-local primitive mutation in the active exact batch."""

        return stage_exact_publication_row(
            self,
            content,
            publish=lambda key, digest, frozen: self._commit_exact_publication_mutation(
                key,
                digest,
                frozen,
                mutation,
            ),
            release=self._release_exact_buffer_row,
        )

    def _commit_exact_publication_mutation(
        self,
        key: ExactPublicationKey,
        digest: str,
        frozen: object,
        mutation: Callable[[], None],
    ) -> None:
        """Commit one list/queue mutation with a retained idempotency receipt."""

        participant_key = key[:2]
        with self._exact_publication_condition:
            if participant_key not in self._active_exact_publication_keys:
                raise ExactPublicationError("Exact mutation lost its emitter fence")
            with self._file_lock:
                retained = self._exact_publication_receipts.get(key)
                if retained is not None:
                    if retained != digest:
                        raise RuntimeError("Exact emitter publication content changed on retry")
                    return
                mutation()
                self._exact_publication_receipts[key] = digest

    def _release_exact_buffer_row(self, key: ExactPublicationKey) -> None:
        """Release one terminal exact-publication receipt."""

        with self._file_lock:
            self._exact_publication_receipts.pop(key, None)
            self._exact_file_pending.pop(key, None)

    def flush(self) -> None:
        """Flush buffered events to disk (thread-safe)."""
        self._wait_for_exact_publication_turn(None)
        with self._file_lock:
            self._flush_unlocked()

    def _flush_unlocked(self) -> None:
        """Internal flush implementation (must hold _file_lock).

        Private method called while already holding the lock.
        """
        if not self.buffer:
            return

        # Ensure header is written first (or mark as done if no header)
        if not self._header_written:
            self._write_header_unlocked()
            # Mark header as written even if no header template exists,
            # so subsequent flushes use append mode instead of truncating
            self._header_written = True

        # Ensure output directory exists
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        # Append buffered events to file
        mode = "a" if self._header_written else "w"
        with open(self.output_path, mode, encoding=self.format_def.output.encoding) as f:
            for event in self.buffer:
                f.write(event)
                if not event.endswith("\n"):
                    f.write("\n")

        # Clear buffer immediately to release memory
        self.buffer.clear()

    def close(self) -> None:
        """Close emitter and flush any remaining events, then write footer."""
        if not self._begin_close():
            return
        drained = False
        try:
            self._wait_for_exact_publication_turn(None)
            if self.threaded:
                self.stop_thread()
            self.flush()
            drained = True
            self._write_footer()
        except BaseException:
            footer_template = getattr(self.format_def.output, "footer_template", None)
            footer_required = bool(footer_template and self._header_written)
            if drained and (not footer_required or self._footer_written):
                self._finish_close()
            else:
                self._fail_close()
            raise
        self._finish_close()

    def _write_footer(self) -> None:
        """Write footer to output file if format has one."""
        footer_template = getattr(self.format_def.output, "footer_template", None)
        if footer_template and self._header_written:
            tmpl = self._template_env.from_string(footer_template)
            footer = tmpl.render()
            encoded = footer if footer.endswith("\n") else f"{footer}\n"
            payload = encoded.encode(self.format_def.output.encoding)
            digest = hashlib.sha256(payload).hexdigest()
            with self._file_lock:
                if self._footer_written:
                    return
                if self._footer_pending is None:
                    offset = self.output_path.stat().st_size
                    self._footer_pending = (digest, offset, len(payload))
                pending_digest, offset, payload_length = self._footer_pending
                if pending_digest != digest or payload_length != len(payload):
                    raise ExactPublicationError("Emitter footer changed during retry")
                with self.output_path.open("r+b") as output:
                    output.seek(offset)
                    retained = output.read(payload_length)
                    if retained == payload:
                        output.flush()
                        os.fsync(output.fileno())
                    else:
                        if retained:
                            if not payload.startswith(retained):
                                raise ExactPublicationError(
                                    "Emitter footer found conflicting bytes"
                                )
                            output.seek(0, os.SEEK_END)
                            if output.tell() != offset + len(retained):
                                raise ExactPublicationError(
                                    "Emitter footer partial write was overtaken"
                                )
                            output.truncate(offset)
                        output.seek(offset)
                        output.write(payload)
                        output.flush()
                        os.fsync(output.fileno())
                fsync_directory(self.output_path.parent)
                self._footer_written = True

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded, independent accounting of canonical Mac births and image activations.

State records obligations before source qualification. Native publication builds a
separate multiset fingerprint from committed source receipts. Counts and SHA-256
fingerprints detect omissions, duplicates and substitutions without retaining a
duration-growing process list. Exact native identity proofs remain owned by the
existing canonical publication contracts.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evidenceforge.events.identity import ProcessIdentity

_MODULUS = 1 << 256
_ZERO = "0" * 64
_MAX_SAMPLES = 8


@dataclass(frozen=True, slots=True)
class MacosOccurrenceDigest:
    """Order-independent, multiplicity-preserving occurrence fingerprint."""

    count: int = 0
    digest: str = _ZERO

    def __post_init__(self) -> None:
        """Reject malformed checkpoint counters and fingerprints."""
        if (
            type(self.count) is not int
            or self.count < 0
            or type(self.digest) is not str
            or len(self.digest) != 64
            or any(char not in "0123456789abcdef" for char in self.digest)
            or (self.count == 0 and self.digest != _ZERO)
        ):
            raise ValueError("Invalid Mac process occurrence digest")

    def add(self, hostname: str, occurrence_id: str) -> MacosOccurrenceDigest:
        """Add one exact host-scoped occurrence, including duplicate multiplicity."""
        encoded = json.dumps([hostname, occurrence_id], separators=(",", ":")).encode()
        value = (int(self.digest, 16) + int.from_bytes(hashlib.sha256(encoded).digest())) % _MODULUS
        return MacosOccurrenceDigest(self.count + 1, f"{value:064x}")


@dataclass(frozen=True, slots=True)
class MacosAggregateBirthSample:
    """One bounded actionable example of an unresolved initial activation."""

    image: str
    started_at: datetime

    def __post_init__(self) -> None:
        """Keep diagnostic examples bounded and schema validated."""
        if (
            type(self.image) is not str
            or not 1 <= len(self.image) <= 1024
            or type(self.started_at) is not datetime
            or self.started_at.utcoffset() is None
        ):
            raise ValueError("Invalid Mac aggregate birth sample")


@dataclass(frozen=True, slots=True)
class MacosProcessCensus:
    """One host's simulation-window obligations, independent of selected outputs."""

    start: datetime
    end: datetime
    forks: MacosOccurrenceDigest = MacosOccurrenceDigest()
    execs: MacosOccurrenceDigest = MacosOccurrenceDigest()
    aggregate_births: int = 0
    aggregate_samples: tuple[MacosAggregateBirthSample, ...] = ()

    def __post_init__(self) -> None:
        """Validate persisted bounds without scanning any process history."""
        if (
            type(self.start) is not datetime
            or type(self.end) is not datetime
            or self.start.utcoffset() != UTC.utcoffset(self.start)
            or self.end.utcoffset() != UTC.utcoffset(self.end)
            or self.start >= self.end
            or type(self.forks) is not MacosOccurrenceDigest
            or type(self.execs) is not MacosOccurrenceDigest
            or type(self.aggregate_births) is not int
            or not 0 <= self.aggregate_births <= self.execs.count
            or type(self.aggregate_samples) is not tuple
            or len(self.aggregate_samples) != min(_MAX_SAMPLES, self.aggregate_births)
            or any(
                type(sample) is not MacosAggregateBirthSample
                or not self.contains(sample.started_at)
                for sample in self.aggregate_samples
            )
        ):
            raise ValueError("Invalid Mac process census")

    def contains(self, at: datetime) -> bool:
        """Use the same half-open interval as exported simulation evidence."""
        return self.start <= at < self.end

    def birth(self, identity: ProcessIdentity, *, forked: bool) -> MacosProcessCensus:
        """Count a fork or unresolved born-image activation at canonical commit."""
        if not self.contains(identity.started_at):
            return self
        if forked:
            return replace(
                self, forks=self.forks.add(identity.hostname, f"process-fork:{identity.object_id}")
            )
        sample = MacosAggregateBirthSample(identity.image[:1024], identity.started_at)
        return replace(
            self,
            execs=self.execs.add(identity.hostname, f"process-exec:{identity.execution_id}"),
            aggregate_births=self.aggregate_births + 1,
            aggregate_samples=(*self.aggregate_samples, sample)[:_MAX_SAMPLES],
        )

    def execute(self, identity: ProcessIdentity) -> MacosProcessCensus:
        """Count a successful image replacement even in a pre-existing lifetime."""
        if not self.contains(identity.execution_started_at):
            return self
        return replace(
            self, execs=self.execs.add(identity.hostname, f"process-exec:{identity.execution_id}")
        )

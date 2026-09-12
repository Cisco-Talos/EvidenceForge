# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit resource ownership for discard-only checkpoint verification."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal, Protocol, cast


class VerificationResourceOwner(Protocol):
    """An owner that declares its scratch resources during construction."""

    _verification_resources: VerificationResources


class _VerificationWorkerOwner(Protocol):
    _verification_discard: bool


ResourceKind = Literal["connection", "descriptor", "child", "children"]


@dataclass
class VerificationResources:
    """Named, owner-declared handles; discovery never guesses from object contents."""

    owner: object
    registrations: list[tuple[ResourceKind, str]] = field(default_factory=list)
    worker: bool = False

    def register(self, kind: ResourceKind, *attributes: str) -> None:
        """Register resource slots before lazy allocation can populate them."""
        self.registrations.extend((kind, attribute) for attribute in attributes)

    def discard(self, disposal: VerificationDisposal) -> None:
        """Stop this owner's worker and discard exactly its registered resources."""
        if self.worker:
            stop_event = getattr(self.owner, "_stop_event", None)
            worker = getattr(self.owner, "_thread", None)
            if stop_event is not None and worker is not None and worker.is_alive():
                cast(_VerificationWorkerOwner, self.owner)._verification_discard = True
                stop_event.set()
                worker.join(timeout=5.0)
                if worker.is_alive():
                    disposal.failures.append(
                        RuntimeError("checkpoint verification worker did not stop")
                    )
        for kind, attribute in self.registrations:
            value = getattr(self.owner, attribute, None)
            if value is None:
                continue
            if kind == "child":
                disposal.pending.append(value._verification_resources)
            elif kind == "children":
                disposal.pending.extend(child._verification_resources for child in value.values())
            elif kind == "connection":
                try:
                    value.close()
                except sqlite3.Error as error:
                    disposal.failures.append(error)
                else:
                    setattr(self.owner, attribute, None)
            elif value in disposal.closed_descriptors:
                setattr(self.owner, attribute, None)
            elif value > 2:
                try:
                    os.close(value)
                except OSError as error:
                    disposal.failures.append(error)
                else:
                    disposal.closed_descriptors.add(value)
                    setattr(self.owner, attribute, None)


@dataclass
class VerificationDisposal:
    """One discard operation's shared-handle and error accounting."""

    pending: list[VerificationResources] = field(default_factory=list)
    closed_descriptors: set[int] = field(default_factory=set)
    failures: list[BaseException] = field(default_factory=list)

    def run(self) -> None:
        """Attempt every registered owner once, retaining the first close failure."""
        visited: set[int] = set()
        while self.pending:
            resources = self.pending.pop()
            if id(resources.owner) in visited:
                continue
            visited.add(id(resources.owner))
            resources.discard(self)
        if self.failures:
            first, *additional = self.failures
            for failure in additional:
                first.add_note(f"Additional scratch disposal failure: {failure!r}")
            raise first


def discard_verification_resources(owners: Iterable[VerificationResourceOwner]) -> None:
    """Discard resources through the owner contract, without source finalization."""
    VerificationDisposal(pending=[owner._verification_resources for owner in owners]).run()

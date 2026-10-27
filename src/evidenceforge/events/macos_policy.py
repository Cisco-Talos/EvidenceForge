# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical identity of a reported policy-refusal target, without an execution."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath

from evidenceforge.events.identity import EntityIdentity


def validate_policy_refusal_image(image: str) -> None:
    """Require one bounded app executable without control text or traversal."""
    if (
        type(image) is not str
        or not image.startswith("/")
        or any(char in image for char in ("\0", "\n", "\r"))
        or ".." in PurePosixPath(image).parts
        or ".app/Contents/MacOS/" not in image
        or not image.rsplit("/", 1)[-1]
    ):
        raise ValueError("Policy-refused app requires an absolute bundle executable path")


@dataclass(frozen=True, slots=True)
class MacosPolicyRefusalTarget:
    """One failed app-launch target named by a policy observation.

    The PID is owned by the host namespace. It is not a ProcessIdentity and does
    not establish parentage, fork, successful image replacement or exit status.
    The allocation position supports exact State validation, not native output.
    """

    hostname: str
    object_id: str
    pid: int
    image: str
    refused_at: datetime
    allocation_position: int

    def __post_init__(self) -> None:
        if not self.hostname or not self.object_id:
            raise ValueError("Policy refusal requires an exact host and target identity")
        if type(self.pid) is not int or not 0 < self.pid < 100000:
            raise ValueError("Policy refusal requires a host-allocated Mac PID")
        if type(self.allocation_position) is not int or self.allocation_position <= 0:
            raise ValueError("Policy refusal requires its positive logical allocation position")
        validate_policy_refusal_image(self.image)
        if type(self.refused_at) is not datetime or self.refused_at.utcoffset() is None:
            raise ValueError("Policy refusal requires an aware occurrence time")

    @property
    def entity(self) -> EntityIdentity:
        """Return the attempt subject, explicitly distinct from a process lifetime."""
        return EntityIdentity(self.object_id, "process_attempt", self.hostname, self.image)


@dataclass(frozen=True, slots=True)
class MacosPolicyRefusalReceipt:
    """Retained State proof for one attempt and its reserved logging thread ID."""

    target: MacosPolicyRefusalTarget
    kernel_thread_id: int
    initiator_object_id: str

    def __post_init__(self) -> None:
        if type(self.target) is not MacosPolicyRefusalTarget:
            raise ValueError("Refusal receipt requires its exact target")
        if type(self.kernel_thread_id) is not int or not 0 < self.kernel_thread_id < 2**64:
            raise ValueError("Refusal receipt requires a positive logging TID")
        if type(self.initiator_object_id) is not str or not self.initiator_object_id:
            raise ValueError("Refusal receipt requires its exact initiating process object")

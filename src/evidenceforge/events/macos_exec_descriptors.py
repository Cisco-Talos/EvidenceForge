# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit source observations of canonical descriptors at one successful exec."""

from dataclasses import dataclass

from evidenceforge.events.macos_descriptors import MacosDescriptorTable


@dataclass(frozen=True, slots=True)
class MacosNativeDescriptor:
    """An observed native tag/pipe identifier for an existing open-object binding.

    The initial profile admits vnode and pipe tags already represented by the
    historical wire contract. It does not allocate pipe IDs or infer them from
    descriptor numbers, file inodes or opaque canonical object IDs.
    """

    fd: int
    object_id: str
    fdtype: int
    pipe_id: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.fd) is not int
            or not 0 <= self.fd < 2**31
            or type(self.object_id) is not str
            or not self.object_id.strip()
            or "\0" in self.object_id
            or type(self.fdtype) is not int
            or self.fdtype not in {1, 6}
            or (
                self.fdtype == 6
                and (type(self.pipe_id) is not int or not 0 <= self.pipe_id < 2**64)
            )
            or (self.fdtype != 6 and self.pipe_id is not None)
        ):
            raise ValueError("Native descriptor requires an exact supported tag and object binding")


@dataclass(frozen=True, slots=True)
class MacosExecDescriptorObservation:
    """Complete explicit FD observation, not an automatic native-object provider.

    ``last_fd`` is a separately supplied native field. Do not derive it from
    table length or the largest descriptor. The canonical table owns inherited
    descriptors and close-on-exec outcomes; this observation owns native tags.
    Cross-event native object identity remains the producer's responsibility.
    """

    table: MacosDescriptorTable
    descriptors: tuple[MacosNativeDescriptor, ...]
    last_fd: int

    def __post_init__(self) -> None:
        if (
            type(self.table) is not MacosDescriptorTable
            or type(self.descriptors) is not tuple
            or len(self.descriptors) > 4096
            or any(type(item) is not MacosNativeDescriptor for item in self.descriptors)
            or type(self.last_fd) is not int
            or not -(2**31) <= self.last_fd < 2**31
        ):
            raise ValueError("Exec FD observation requires an exact bounded table and native field")
        self.table.__post_init__()
        for item in self.descriptors:
            item.__post_init__()
        if tuple((item.fd, item.object_id) for item in self.descriptors) != tuple(
            (item.fd, item.object_id) for item in self.table.bindings
        ):
            raise ValueError("Exec FD observation must cover every canonical binding exactly once")
        object_tags: dict[str, tuple[int, int | None]] = {}
        for binding, native in zip(self.table.bindings, self.descriptors, strict=True):
            if binding.kind != ("pipe" if native.fdtype == 6 else "file"):
                raise ValueError("Native FD tag contradicts its canonical open-object kind")
            tag = (native.fdtype, native.pipe_id)
            if object_tags.setdefault(binding.object_id, tag) != tag:
                raise ValueError(
                    "Shared open object has conflicting native descriptor observations"
                )

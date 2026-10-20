# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit modeled descriptor ownership, independent of native export layouts."""

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field


@dataclass(frozen=True, slots=True)
class MacosDescriptorBinding:
    """One descriptor referring to an already modeled open object.

    Object identity is shared by duplicated/inherited descriptors; a descriptor
    number is process-local. This does not allocate files, pipes, sockets or
    native kernel IDs, and it does not assert an ES fdtype value.
    """

    fd: Annotated[int, Field(strict=True, ge=0, lt=2**31)]
    kind: Literal["file", "pipe", "socket"]
    object_id: Annotated[str, Field(strict=True, min_length=1)]
    close_on_exec: Annotated[bool, Field(strict=True)]
    native_pipe_id: Annotated[int, Field(strict=True, ge=0, lt=2**64)] | None = None

    def __post_init__(self) -> None:
        if (
            type(self.fd) is not int
            or not 0 <= self.fd < 2**31
            or type(self.kind) is not str
            or self.kind not in {"file", "pipe", "socket"}
            or type(self.object_id) is not str
            or not self.object_id.strip()
            or "\0" in self.object_id
            or type(self.close_on_exec) is not bool
            or (
                self.native_pipe_id is not None
                and (
                    self.kind != "pipe"
                    or type(self.native_pipe_id) is not int
                    or not 0 <= self.native_pipe_id < 2**64
                )
            )
        ):
            raise ValueError("Mac descriptor requires an exact number, object kind and ownership")


@dataclass(frozen=True, slots=True)
class MacosDescriptorTable:
    """A complete bounded table at a canonical instant; empty is known empty.

    A missing table in State means unknown. Filesystem metadata and socket or
    pipe internals belong to their own owners. Descriptor sharing here does not
    infer shared offsets, native IDs or access modes.
    """

    hostname: Annotated[str, Field(strict=True, min_length=1)]
    observed_at: Annotated[datetime, Field(strict=True)]
    bindings: Annotated[tuple[MacosDescriptorBinding, ...], Field(strict=True, max_length=4096)]
    native_last_fd: Annotated[int, Field(strict=True, ge=-1, lt=2**31)] | None = None

    def __post_init__(self) -> None:
        if (
            type(self.hostname) is not str
            or not self.hostname.strip()
            or "\0" in self.hostname
            or type(self.observed_at) is not datetime
            or self.observed_at.utcoffset() is None
            or type(self.bindings) is not tuple
            or len(self.bindings) > 4096
            or any(type(item) is not MacosDescriptorBinding for item in self.bindings)
        ):
            raise ValueError(
                "Mac descriptor table requires exact host, aware time and bounded bindings"
            )
        object_kinds: dict[str, str] = {}
        for item in self.bindings:
            item.__post_init__()
            previous = object_kinds.setdefault(item.object_id, item.kind)
            if previous != item.kind:
                raise ValueError("One shared descriptor object cannot have conflicting kinds")
        numbers = tuple(item.fd for item in self.bindings)
        if numbers != tuple(sorted(set(numbers))):
            raise ValueError("Mac descriptor table requires sorted unique descriptor numbers")
        if self.native_last_fd is not None and (
            type(self.native_last_fd) is not int or self.native_last_fd != max(numbers, default=-1)
        ):
            raise ValueError("Complete native descriptor extent disagrees with its full table")
        object_pipes: dict[str, int | None] = {}
        for item in self.bindings:
            if object_pipes.setdefault(item.object_id, item.native_pipe_id) != item.native_pipe_id:
                raise ValueError("Shared pipe descriptors require one exact native pipe identity")

    def _with_bindings(
        self, bindings: tuple[MacosDescriptorBinding, ...]
    ) -> "MacosDescriptorTable":
        return replace(
            self,
            bindings=bindings,
            native_last_fd=(
                max((item.fd for item in bindings), default=-1)
                if self.native_last_fd is not None
                else None
            ),
        )

    def _at(self, observed_at: datetime) -> "MacosDescriptorTable":
        if (
            type(observed_at) is not datetime
            or observed_at.utcoffset() is None
            or observed_at < self.observed_at
        ):
            raise ValueError("Descriptor transition cannot precede its known table")
        return replace(self, observed_at=observed_at)

    def inherited_at(self, observed_at: datetime) -> "MacosDescriptorTable":
        """Copy a known table into a forked lifetime, preserving open-object sharing."""
        return self._at(observed_at)

    def after_exec(self, observed_at: datetime) -> "MacosDescriptorTable":
        """Close only explicitly marked descriptors after successful image replacement."""
        return self._at(observed_at)._with_bindings(
            tuple(item for item in self.bindings if not item.close_on_exec)
        )

    def opened(
        self, binding: MacosDescriptorBinding, *, observed_at: datetime
    ) -> "MacosDescriptorTable":
        """Add an explicitly allocated free descriptor without allocating an open object."""
        if type(binding) is not MacosDescriptorBinding or any(
            item.fd == binding.fd for item in self.bindings
        ):
            raise ValueError("Descriptor open requires an exact binding and unused number")
        return self._at(observed_at)._with_bindings(
            tuple(sorted((*self.bindings, binding), key=lambda item: item.fd))
        )

    def closed(self, fd: int, *, observed_at: datetime) -> "MacosDescriptorTable":
        """Remove one known descriptor without closing another process's shared reference."""
        if type(fd) is not int or not any(item.fd == fd for item in self.bindings):
            raise ValueError("Descriptor close requires an existing exact number")
        return self._at(observed_at)._with_bindings(
            tuple(item for item in self.bindings if item.fd != fd)
        )

    def duplicated(
        self, source_fd: int, target_fd: int, *, observed_at: datetime, close_on_exec: bool
    ) -> "MacosDescriptorTable":
        """Duplicate to an explicit free number with an explicitly supplied descriptor flag.

        Replacement of an occupied descriptor and shared-offset changes require
        their own operation semantics; this bounded helper does not model dup2.
        """
        if type(source_fd) is not int:
            raise ValueError("Descriptor duplication requires an exact source number")
        source = next((item for item in self.bindings if item.fd == source_fd), None)
        if source is None:
            raise ValueError("Descriptor duplication requires an existing source")
        return self.opened(
            replace(source, fd=target_fd, close_on_exec=close_on_exec), observed_at=observed_at
        )

    def duplicate_to(
        self, source_fd: int, target_fd: int, *, observed_at: datetime
    ) -> "MacosDescriptorTable":
        """Apply successful dup2 table semantics, retaining shared open-object identity.

        An occupied destination loses only its descriptor binding. A distinct
        destination clears close-on-exec; duplicating a descriptor onto itself
        preserves its flags. This does not infer final object destruction or
        shared-offset effects, and it does not simulate failed syscalls.
        """
        if type(source_fd) is not int or type(target_fd) is not int or not 0 <= target_fd < 2**31:
            raise ValueError("Descriptor duplication requires exact valid numbers")
        source = next((item for item in self.bindings if item.fd == source_fd), None)
        if source is None:
            raise ValueError("Descriptor duplication requires an existing source")
        at = self._at(observed_at)
        if source_fd == target_fd:
            return at
        copied = replace(source, fd=target_fd, close_on_exec=False)
        retained = tuple(item for item in self.bindings if item.fd != target_fd)
        return at._with_bindings(tuple(sorted((*retained, copied), key=lambda item: item.fd)))

    def set_close_on_exec(
        self, fd: int, enabled: bool, *, observed_at: datetime
    ) -> "MacosDescriptorTable":
        """Apply an explicit successful descriptor-flag change without changing the open object."""
        if (
            type(fd) is not int
            or type(enabled) is not bool
            or not any(item.fd == fd for item in self.bindings)
        ):
            raise ValueError("Descriptor flags require an existing exact number and Boolean flag")
        return replace(
            self._at(observed_at),
            bindings=tuple(
                replace(item, close_on_exec=enabled) if item.fd == fd else item
                for item in self.bindings
            ),
        )


def validate_macos_descriptors(
    table: MacosDescriptorTable, *, hostname: str, observed_at: datetime, platform: str
) -> None:
    """Require complete descriptor facts to belong to this exact Mac occurrence."""
    if type(table) is not MacosDescriptorTable:
        raise ValueError("Mac descriptors require an exact table")
    table.__post_init__()
    if platform != "macos" or table.hostname != hostname or table.observed_at != observed_at:
        raise ValueError("Mac descriptors require their exact host and observation time")

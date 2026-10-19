# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit modeled Mac file metadata, independent of paths and content hashes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

type _Unsigned32 = Annotated[int, Field(ge=0, lt=2**32)]
type _Signed32 = Annotated[int, Field(ge=-(2**31), lt=2**31)]
type _Unsigned16 = Annotated[int, Field(ge=0, lt=2**16)]


class MacosFileTime(BaseModel):
    """An exact modeled Unix timespec; datetime conversion never loses nanoseconds."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    seconds: int = Field(description="Signed Unix seconds")
    nanoseconds: int = Field(ge=0, lt=1_000_000_000)

    @model_validator(mode="after")
    def representable_time(self) -> Self:
        """Bound the modeled timestamp to the native textual export calendar."""
        try:
            datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=self.seconds)
        except (OverflowError, ValueError) as error:
            raise ValueError("Mac file timestamp exceeds the supported calendar") from error
        return self

    def native_timestamp(self) -> str:
        """Render exact UTC nanoseconds without sampling a clock."""
        time = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=self.seconds)
        return f"{time.isoformat(timespec='seconds')[:19]}.{self.nanoseconds:09d}Z"


class MacosFileMetadata(BaseModel):
    """Complete regular-file stat facts supplied by the canonical file producer.

    Volume and file-object IDs are modeled identities, never path hashes. This
    value describes one published version; it does not infer timestamps, inode
    allocation, sparse/compressed allocation, or permissions from content.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    volume_id: str = Field(min_length=1, max_length=256)
    file_object_id: str = Field(min_length=1, max_length=256)
    device: _Signed32
    inode: int = Field(ge=1, lt=2**64)
    mode: _Unsigned16
    link_count: _Unsigned16
    uid: _Unsigned32
    gid: _Unsigned32
    special_device: _Signed32
    accessed: MacosFileTime
    modified: MacosFileTime
    changed: MacosFileTime
    born: MacosFileTime
    size_bytes: int = Field(ge=0, lt=2**63)
    allocated_blocks: int = Field(ge=0, lt=2**63, description="Allocated 512-byte units")
    preferred_block_size: int = Field(gt=0, lt=2**31)
    flags: _Unsigned32
    generation: _Unsigned32

    @model_validator(mode="after")
    def regular_file(self) -> Self:
        """Keep this initial producer profile limited to explicit regular files."""
        if self.mode & 0o170000 != 0o100000 or self.special_device != 0:
            raise ValueError("Mac runtime file metadata requires a regular file")
        if any(
            "\0" in value or not value.strip() for value in (self.volume_id, self.file_object_id)
        ):
            raise ValueError("Mac file metadata requires NUL-free modeled object identities")
        return self

    def canonical_json(self) -> str:
        """Validate primitive fields before serializing a publication integrity preimage."""
        if type(self) is not MacosFileMetadata:
            raise ValueError("Mac file metadata requires its exact immutable type")
        values: dict[str, object] = {}
        for name in MacosFileMetadata.model_fields:
            value = getattr(self, name)
            if name in {"accessed", "modified", "changed", "born"}:
                if type(value) is not MacosFileTime or any(
                    type(part) is not int for part in (value.seconds, value.nanoseconds)
                ):
                    raise ValueError("Mac file times require exact integer snapshots")
                values[name] = MacosFileTime(seconds=value.seconds, nanoseconds=value.nanoseconds)
            else:
                expected = str if name in {"volume_id", "file_object_id"} else int
                if type(value) is not expected:
                    raise ValueError("Mac file metadata contains a non-primitive field")
                values[name] = value
        return MacosFileMetadata.model_validate(values).model_dump_json()

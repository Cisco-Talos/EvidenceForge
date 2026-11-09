# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit arm64 image-slice and pre-resolution exec-path facts."""

from dataclasses import dataclass
from typing import Annotated

from pydantic import Field

# Darwin's CPU_TYPE_ARM64 ABI value; this is a type code, not a workload default.
ARM64_CPU_TYPE = 0x0100000C


@dataclass(frozen=True, slots=True)
class MacosExecImage:
    """Immutable facts belonging to an execution's selected native arm64 image.

    Subtype must be supplied, never guessed from host architecture. The dyld
    value is the exec path passed to dyld before symlink resolution, not the
    path to the dynamic loader. Preserve its spelling, including relative path
    components; None means unknown. No filesystem or environment is inspected.
    """

    cpu_subtype: Annotated[int, Field(strict=True, ge=-(2**31), lt=2**31)]
    dyld_exec_path: Annotated[str, Field(strict=True)] | None = None

    def __post_init__(self) -> None:
        if type(self.cpu_subtype) is not int or not -(2**31) <= self.cpu_subtype < 2**31:
            raise ValueError("Mac execution image requires an explicit signed CPU subtype")
        if self.dyld_exec_path is not None and (
            type(self.dyld_exec_path) is not str or "\0" in self.dyld_exec_path
        ):
            raise ValueError("Mac dyld exec path requires an explicit NUL-free string")


def validate_macos_exec_image(value: MacosExecImage | None, platform: str) -> None:
    """Reject foreign-platform or malformed execution-image metadata before allocation."""
    if value is not None:
        if platform != "macos" or type(value) is not MacosExecImage:
            raise ValueError("Mac execution image requires an exact macOS snapshot")
        value.__post_init__()

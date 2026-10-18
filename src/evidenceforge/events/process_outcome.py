# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit terminal POSIX process results, distinct from signal requests."""

from dataclasses import dataclass
from typing import Annotated

from pydantic import Field, StrictBool


@dataclass(frozen=True, slots=True)
class PosixProcessExit:
    """One observed terminal result; absence remains unknown, never success.

    Signal numbers use the modeled host's ABI. The core flag describes the
    termination result and does not establish a collected core-file artifact.
    """

    exit_code: Annotated[int, Field(strict=True, ge=0, le=255)] | None = None
    signal: Annotated[int, Field(strict=True, ge=1, lt=127)] | None = None
    core_dumped: StrictBool = False

    def __post_init__(self) -> None:
        """Reject ambiguous outcomes, nonterminal statuses and coerced scalars."""
        if type(self.core_dumped) is not bool:
            raise ValueError("Process exit core flag requires an exact boolean")
        if (self.exit_code is None) == (self.signal is None):
            raise ValueError("Process exit requires exactly one exit code or termination signal")
        if self.exit_code is not None:
            if type(self.exit_code) is not int or not 0 <= self.exit_code <= 255:
                raise ValueError("POSIX exit code must be an integer from 0 to 255")
            if self.core_dumped:
                raise ValueError("Normal process exit cannot carry a core-dump flag")
        elif type(self.signal) is not int or not 1 <= self.signal < 127:
            raise ValueError("POSIX termination signal must be an integer from 1 to 126")

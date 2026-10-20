# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit image-security state, separate from static signer and collector identity."""

from dataclasses import dataclass
from typing import Annotated

from pydantic import Field


@dataclass(frozen=True, slots=True)
class MacosImageSecurity:
    """A bounded execution's modeled runtime code-validation state.

    Producers must supply flags; a static signature or application catalog is
    insufficient. This profile retains the supplied state through fork and
    replaces it on exec. In-execution invalidation/debugger transitions are not
    modeled, and ES-client attachment is deliberately a separate fact.
    """

    codesigning_flags: Annotated[int, Field(strict=True, ge=0, lt=2**32)]
    is_platform_binary: Annotated[bool, Field(strict=True)]
    validation_category: Annotated[int, Field(strict=True, ge=0, lt=2**32)] | None = None

    def __post_init__(self) -> None:
        if (
            type(self.codesigning_flags) is not int
            or not 0 <= self.codesigning_flags < 2**32
            or type(self.is_platform_binary) is not bool
            or (
                self.validation_category is not None
                and (
                    type(self.validation_category) is not int
                    or not 0 <= self.validation_category < 2**32
                )
            )
        ):
            raise ValueError("Mac image security requires exact runtime flags and category")


def validate_macos_image_security(value: MacosImageSecurity | None, platform: str) -> None:
    """Reject foreign-platform metadata before process allocation."""
    if value is not None:
        if platform != "macos" or type(value) is not MacosImageSecurity:
            raise ValueError("Mac image security requires an exact macOS execution snapshot")
        value.__post_init__()


@dataclass(frozen=True, slots=True)
class MacosCodeValidationDecision:
    """Explicit execution-owner result bound to one immutable binary content ID."""

    content_id: str
    security: MacosImageSecurity

    def __post_init__(self) -> None:
        if type(self.content_id) is not str or not self.content_id or "\0" in self.content_id:
            raise ValueError("Mac validation decision requires an exact binary content identity")
        if type(self.security) is not MacosImageSecurity:
            raise ValueError("Mac validation decision requires exact runtime security facts")
        self.security.__post_init__()

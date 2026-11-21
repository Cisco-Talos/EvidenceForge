# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed engine policy for automatically populated storage metadata sizes."""

from __future__ import annotations

import re
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StorageFileSizeSupport(BaseModel):
    """Inclusive byte support for one automatic file population."""

    minimum_bytes: int = Field(
        gt=0, le=2**63 - 1, strict=True, description="Smallest automatic file size in bytes"
    )
    maximum_bytes: int = Field(
        gt=0, le=2**63 - 1, strict=True, description="Largest automatic file size in bytes"
    )
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def ordered_support(self) -> Self:
        """Reject reversed byte support before compiling any file identities."""
        if self.maximum_bytes < self.minimum_bytes:
            raise ValueError("maximum_bytes must be at least minimum_bytes")
        return self


class StorageFileSizePolicy(BaseModel):
    """Purpose/type routing independent of portable storage vocabulary profiles."""

    default_profile: str = Field(min_length=1, description="Fallback size profile identity")
    preset_profiles: dict[str, str] = Field(
        default_factory=dict, description="Fallback size profile for each catalog preset"
    )
    extension_profiles: dict[str, str] = Field(
        default_factory=dict, description="Size profile for each lowercase filename suffix"
    )
    preset_extension_profiles: dict[str, dict[str, str]] = Field(
        default_factory=dict, description="Purpose-specific suffix overrides, applied first"
    )
    profiles: dict[str, StorageFileSizeSupport] = Field(
        min_length=1, description="Named automatic byte support profiles"
    )
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def coherent_routes(self) -> Self:
        """Require normalized keys and resolvable profile references."""
        names = [*self.profiles, *self.preset_profiles, *self.preset_extension_profiles]
        if any(not name or name != name.strip() for name in names):
            raise ValueError("size policy profile and preset names must be nonempty and trimmed")
        extension_tables = [self.extension_profiles, *self.preset_extension_profiles.values()]
        if any(
            not re.fullmatch(r"\.[a-z0-9][a-z0-9._+-]*", suffix)
            for table in extension_tables
            for suffix in table
        ):
            raise ValueError("size policy extensions must be lowercase filename suffixes")
        references = {
            self.default_profile,
            *self.preset_profiles.values(),
            *(profile for table in extension_tables for profile in table.values()),
        }
        missing = references - self.profiles.keys()
        if missing:
            raise ValueError(f"size policy routes reference unknown profiles: {sorted(missing)}")
        return self

    def profile_for(self, *, extension: str, preset: str) -> StorageFileSizeSupport:
        """Resolve purpose/type specificity before purpose and default fallbacks."""
        suffix = extension.strip().casefold()
        name = (
            self.preset_extension_profiles.get(preset, {}).get(suffix)
            or self.extension_profiles.get(suffix)
            or self.preset_profiles.get(preset, self.default_profile)
        )
        return self.profiles[name]

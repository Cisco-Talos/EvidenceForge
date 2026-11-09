# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Data-driven fallback sizes for unresolved runtime executable artifacts."""

from __future__ import annotations

import math
import random

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.events.content_identity import Platform
from evidenceforge.utils.rng import _stable_seed


class ExecutableSizeBounds(BaseModel):
    """Inclusive decimal-log bounds for one platform's executable sizes."""

    min: float = Field(ge=0, le=12)
    max: float = Field(ge=0, le=12)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_order(self) -> ExecutableSizeBounds:
        """Require a non-reversed size range."""

        if self.max < self.min:
            raise ValueError("max must be greater than or equal to min")
        return self


class RuntimeExecutableProfile(BaseModel):
    """Positive fallback size range for unresolved executable content."""

    size_log10: ExecutableSizeBounds

    model_config = ConfigDict(frozen=True, extra="forbid")


class RuntimeExecutableProfiles(BaseModel):
    """Validated platform-specific executable size catalog."""

    schema_version: str = Field(min_length=1)
    profiles: dict[Platform, RuntimeExecutableProfile] = Field(min_length=3)

    model_config = ConfigDict(frozen=True, extra="forbid")


def load_runtime_executable_profiles() -> RuntimeExecutableProfiles:
    """Load and validate platform-specific fallback size ranges."""

    path = get_activity_directory() / "runtime_executable_profiles.yaml"
    data = load_with_overlay(path, "activity/runtime_executable_profiles.yaml", deep_merge_dict)
    return RuntimeExecutableProfiles.model_validate(data)


def runtime_executable_size_bytes(*, platform: Platform, stable_id: str) -> int:
    """Return a deterministic positive content size for an unresolved executable."""

    if platform not in {"windows", "linux", "macos"}:
        raise ValueError("runtime executable size requires a supported platform")
    if not isinstance(stable_id, str) or not stable_id.strip():
        raise ValueError("runtime executable sizing requires a stable identity")
    profile = load_runtime_executable_profiles().profiles[platform].size_log10
    rng = random.Random(_stable_seed(f"runtime_executable_size:{platform}:{stable_id}"))
    return max(1, math.ceil(10 ** rng.uniform(profile.min, profile.max)))


__all__ = [
    "ExecutableSizeBounds",
    "RuntimeExecutableProfile",
    "RuntimeExecutableProfiles",
    "load_runtime_executable_profiles",
    "runtime_executable_size_bytes",
]

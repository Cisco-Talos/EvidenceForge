# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Data-driven logical sizes for command-owned archive outputs."""

from __future__ import annotations

import random

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.utils.rng import _stable_seed


class LogSizeBounds(BaseModel):
    """Inclusive decimal-log bounds for one output-size profile."""

    min: float = Field(ge=0, le=12)
    max: float = Field(ge=0, le=12)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_order(self) -> LogSizeBounds:
        """Require the maximum size exponent to be at least the minimum."""

        if self.max < self.min:
            raise ValueError("max must be greater than or equal to min")
        return self


class ProcessOutputProfile(BaseModel):
    """Size distribution for a command that creates an archive output."""

    output_size_log10: LogSizeBounds

    model_config = ConfigDict(frozen=True, extra="forbid")


class ProcessOutputProfiles(BaseModel):
    """Validated process output-size catalog."""

    schema_version: str = Field(min_length=1)
    profiles: dict[str, ProcessOutputProfile] = Field(min_length=1)

    model_config = ConfigDict(frozen=True, extra="forbid")


def load_process_output_profiles() -> ProcessOutputProfiles:
    """Load and validate the merged process output-size catalog."""

    path = get_activity_directory() / "process_output_profiles.yaml"
    data = load_with_overlay(
        path,
        "activity/process_output_profiles.yaml",
        deep_merge_dict,
    )
    return ProcessOutputProfiles.model_validate(data)


def process_output_size_bytes(
    *,
    process_name: str,
    command_line: str,
    stable_id: str,
) -> int | None:
    """Return deterministic non-empty size for a recognized archive command."""

    if not all(
        isinstance(value, str) and value.strip()
        for value in (process_name, command_line, stable_id)
    ):
        raise ValueError("process output sizing requires process, command, and stable identities")
    executable = process_name.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    if executable.endswith(".exe"):
        executable = executable[:-4]
    profile_key = executable
    if executable in {"powershell", "pwsh"} and "compress-archive" in command_line.casefold():
        profile_key = "powershell_compress_archive"
    profile = load_process_output_profiles().profiles.get(profile_key)
    if profile is None:
        return None
    bounds = profile.output_size_log10
    rng = random.Random(_stable_seed(f"process_output_size:{stable_id}:{profile_key}"))
    return max(1, int(10 ** rng.uniform(bounds.min, bounds.max)))


__all__ = [
    "ProcessOutputProfile",
    "ProcessOutputProfiles",
    "load_process_output_profiles",
    "process_output_size_bytes",
]

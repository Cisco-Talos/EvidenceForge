# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable source-profile identity retained with an ES connection epoch."""

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class ESCollectorSourceProfile(BaseModel):
    """Bind counter history to its exact frozen native source and modeled boot."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    profile_id: str = Field(min_length=1, max_length=128)
    configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    os_build: str = Field(min_length=1, max_length=128)
    architecture: str = Field(min_length=1, max_length=16)
    message_version: int = Field(ge=1, lt=2**32)
    boot_uuid: str = Field(pattern=r"^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$")
    boot_time: AwareDatetime
    timebase_numerator: int = Field(gt=0, lt=2**32)
    timebase_denominator: int = Field(gt=0, lt=2**32)

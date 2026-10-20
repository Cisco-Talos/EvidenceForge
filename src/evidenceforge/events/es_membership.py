# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit completeness bounds for a modeled host's ES client inventory."""

from typing import Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class ESClientMembershipCoverage(BaseModel):
    """A complete modeled inventory over a half-open interval, never discovery.

    Every client on this host must use an exact registered execution. Earlier
    discarded connection epochs cannot support a negative membership claim.
    This assertion is supplied by the model owner, not inferred from absence.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    hostname: str = Field(min_length=1, max_length=256, pattern=r"\S")
    known_from: AwareDatetime
    known_until: AwareDatetime

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.known_from >= self.known_until:
            raise ValueError("ES membership coverage requires a nonempty finite interval")
        return self

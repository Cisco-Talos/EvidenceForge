# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Scenario and configuration models for correlated IDS alert policies."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

PositiveFilterInt = Annotated[int, Field(strict=True, ge=1, le=2_147_483_647)]
IdsTrackMode = Literal["by_src", "by_dst"]


class IdsDetectionFilterSpec(BaseModel):
    """Snort-style rate threshold required before a rule produces events."""

    track: IdsTrackMode
    count: PositiveFilterInt
    seconds: PositiveFilterInt

    model_config = ConfigDict(extra="forbid", frozen=True)


class IdsEventFilterSpec(BaseModel):
    """Snort-style output filter applied after rule detection."""

    type: Literal["limit", "threshold", "both"]
    track: IdsTrackMode
    count: PositiveFilterInt
    seconds: PositiveFilterInt

    model_config = ConfigDict(extra="forbid", frozen=True)


class IdsAlertPolicySpec(BaseModel):
    """Composable detection and output filters for one IDS signature."""

    detection_filter: IdsDetectionFilterSpec | None = None
    event_filter: IdsEventFilterSpec | None = None

    @model_validator(mode="after")
    def require_filter(self) -> IdsAlertPolicySpec:
        """Reject ambiguous empty objects; use ``every`` explicitly instead."""

        if self.detection_filter is None and self.event_filter is None:
            raise ValueError("IDS alert policy must define detection_filter or event_filter")
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


IdsAlertPolicyOverride = Literal["every"] | IdsAlertPolicySpec


class IdsAlertAttachmentSpec(BaseModel):
    """Reference one configured IDS signature from a canonical network event."""

    sid: Annotated[int, Field(strict=True, ge=1, le=2_147_483_647)]
    policy: IdsAlertPolicyOverride | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)


def policy_fingerprint(policy: IdsAlertPolicySpec | None) -> tuple[object, ...]:
    """Return a stable comparable representation of an effective policy."""

    if policy is None:
        return ("every",)
    detection = policy.detection_filter
    event_filter = policy.event_filter
    return (
        "policy",
        None if detection is None else (detection.track, detection.count, detection.seconds),
        None
        if event_filter is None
        else (event_filter.type, event_filter.track, event_filter.count, event_filter.seconds),
    )

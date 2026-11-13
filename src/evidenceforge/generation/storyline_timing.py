# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed engine-runtime timing helpers for authored storyline activity."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from evidenceforge.generation.timing import (
    ConstantDistribution,
    MixtureDistribution,
    TimingRuntime,
    TimingScope,
    TriangularDistribution,
    TruncatedLognormalDistribution,
    TruncatedNormalDistribution,
    WeightedDistribution,
    uniform_distribution,
)

STORYLINE_EVENT_JITTER_SECONDS = 30


@dataclass(frozen=True, slots=True)
class StorylineTimingPlanner:
    """Sample canonical storyline timing from one shared stateless runtime."""

    runtime: TimingRuntime

    def place_event(
        self,
        nominal_time: datetime,
        *,
        event_id: str,
        host: str,
        section: Literal["storyline", "red_herring"],
    ) -> datetime:
        """Place an authored action through the shared scoped microsecond sampler.

        Retain the authored jitter policy's broad offset plus subsecond phase.
        The semantic event identity makes interleaved and batch execution agree.
        """
        scope = TimingScope(
            stable_id=event_id,
            host=host,
            source=section,
            lifecycle_id=nominal_time.isoformat(),
        )
        relationship = f"{section}.event.placement"
        preferred = self.runtime.sampler.after(
            nominal_time,
            uniform_distribution(
                -STORYLINE_EVENT_JITTER_SECONDS * 1_000_000,
                STORYLINE_EVENT_JITTER_SECONDS * 1_000_000,
            ),
            relationship_key=relationship,
            scope=scope,
            sample_key="jitter",
        )
        return self.runtime.sampler.after(
            preferred,
            uniform_distribution(0, 1_000_000),
            relationship_key=relationship,
            scope=scope,
            sample_key="fractional_phase",
        )

    def _scope(
        self,
        *,
        stable_id: str,
        host: str,
        lifecycle_id: str,
        ordinal: int,
    ) -> TimingScope:
        """Return the semantic scope shared by one authored timing relationship."""

        return TimingScope(
            stable_id=stable_id,
            host=host,
            source="storyline",
            lifecycle_id=lifecycle_id,
            ordinal=ordinal,
        )

    def right_skew_seconds(
        self,
        *,
        relationship_key: str,
        stable_id: str,
        minimum: float,
        median: float,
        maximum: float,
        sigma: float = 0.72,
        host: str = "",
        lifecycle_id: str = "",
        ordinal: int = 0,
        sample_key: str = "seconds",
    ) -> float:
        """Return an open-support right-skew duration in whole microseconds."""

        if maximum <= minimum:
            distribution = ConstantDistribution(minimum * 1_000_000)
        else:
            distribution = TruncatedLognormalDistribution(
                median=max(1.0, median * 1_000_000),
                sigma=max(0.05, sigma),
                minimum=minimum * 1_000_000,
                maximum=maximum * 1_000_000,
            )
        microseconds = self.runtime.sampler.sample_microseconds(
            distribution,
            relationship_key=relationship_key,
            scope=self._scope(
                stable_id=stable_id,
                host=host,
                lifecycle_id=lifecycle_id,
                ordinal=ordinal,
            ),
            sample_key=sample_key,
        )
        return microseconds / 1_000_000

    def centered_seconds(
        self,
        *,
        relationship_key: str,
        stable_id: str,
        mean: float,
        standard_deviation: float,
        minimum: float,
        maximum: float,
        host: str = "",
        lifecycle_id: str = "",
        ordinal: int = 0,
        sample_key: str = "seconds",
    ) -> float:
        """Return an interior truncated-normal offset in seconds."""

        if maximum <= minimum:
            distribution = ConstantDistribution(minimum * 1_000_000)
        else:
            distribution = TruncatedNormalDistribution(
                mean=mean * 1_000_000,
                standard_deviation=max(0.000001, standard_deviation) * 1_000_000,
                minimum=minimum * 1_000_000,
                maximum=maximum * 1_000_000,
            )
        microseconds = self.runtime.sampler.sample_microseconds(
            distribution,
            relationship_key=relationship_key,
            scope=self._scope(
                stable_id=stable_id,
                host=host,
                lifecycle_id=lifecycle_id,
                ordinal=ordinal,
            ),
            sample_key=sample_key,
        )
        return microseconds / 1_000_000

    def triangular_seconds(
        self,
        *,
        relationship_key: str,
        stable_id: str,
        minimum: float,
        mode: float,
        maximum: float,
        host: str = "",
        lifecycle_id: str = "",
        ordinal: int = 0,
        sample_key: str = "seconds",
    ) -> float:
        """Return an interior triangular duration or phase in seconds."""

        if maximum <= minimum:
            distribution = ConstantDistribution(minimum * 1_000_000)
        else:
            distribution = TriangularDistribution(
                minimum * 1_000_000,
                min(maximum, max(minimum, mode)) * 1_000_000,
                maximum * 1_000_000,
            )
        microseconds = self.runtime.sampler.sample_microseconds(
            distribution,
            relationship_key=relationship_key,
            scope=self._scope(
                stable_id=stable_id,
                host=host,
                lifecycle_id=lifecycle_id,
                ordinal=ordinal,
            ),
            sample_key=sample_key,
        )
        return microseconds / 1_000_000

    def mixture_seconds(
        self,
        *,
        relationship_key: str,
        stable_id: str,
        components: tuple[tuple[float, float, float, float, float], ...],
        host: str = "",
        lifecycle_id: str = "",
        ordinal: int = 0,
        sample_key: str = "seconds",
    ) -> float:
        """Return one deterministic sample from weighted right-skew families.

        Components contain ``(weight, minimum, median, maximum, sigma)``.
        """

        weighted: list[WeightedDistribution] = []
        for weight, minimum, median, maximum, sigma in components:
            if maximum <= minimum:
                component = ConstantDistribution(minimum * 1_000_000)
            else:
                component = TruncatedLognormalDistribution(
                    median=max(1.0, median * 1_000_000),
                    sigma=max(0.05, sigma),
                    minimum=minimum * 1_000_000,
                    maximum=maximum * 1_000_000,
                )
            weighted.append(WeightedDistribution(weight, component))
        microseconds = self.runtime.sampler.sample_microseconds(
            MixtureDistribution(tuple(weighted)),
            relationship_key=relationship_key,
            scope=self._scope(
                stable_id=stable_id,
                host=host,
                lifecycle_id=lifecycle_id,
                ordinal=ordinal,
            ),
            sample_key=sample_key,
        )
        return microseconds / 1_000_000

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed engine-runtime timing helpers for baseline and browser activity."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta

from evidenceforge.generation.timing import (
    ConstantDistribution,
    MixtureDistribution,
    TimingDistributionError,
    TimingRuntime,
    TimingScope,
    TriangularDistribution,
    TruncatedLognormalDistribution,
    TruncatedNormalDistribution,
    WeightedDistribution,
)
from evidenceforge.utils.time import ensure_utc


@dataclass(frozen=True, slots=True)
class BaselineTimingPlanner:
    """Sample baseline timing from one shared, stateless engine runtime."""

    runtime: TimingRuntime
    source: str = "baseline"

    @classmethod
    def compatibility(cls, reference_time: datetime) -> BaselineTimingPlanner:
        """Return an isolated adapter for direct helper construction."""

        reference = ensure_utc(reference_time).replace(hour=0, minute=0, second=0, microsecond=0)
        return cls(
            TimingRuntime(reference_time=reference, namespace="baseline-timing-compatibility")
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
        """Return a microsecond-quantized right-skew duration in seconds."""

        if maximum <= minimum:
            distribution = ConstantDistribution(minimum * 1_000_000)
        else:
            distribution = TruncatedLognormalDistribution(
                median=max(1.0, median * 1_000_000),
                sigma=max(0.05, sigma),
                minimum=max(0.0, minimum * 1_000_000),
                maximum=maximum * 1_000_000,
            )
        microseconds = self.runtime.sampler.sample_microseconds(
            distribution,
            relationship_key=relationship_key,
            scope=TimingScope(
                stable_id=stable_id,
                host=host,
                source=self.source,
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
        """Return a microsecond-quantized triangular duration in seconds."""

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
            scope=TimingScope(
                stable_id=stable_id,
                host=host,
                source=self.source,
                lifecycle_id=lifecycle_id,
                ordinal=ordinal,
            ),
            sample_key=sample_key,
        )
        return microseconds / 1_000_000

    def packet_observation_delta(
        self,
        *,
        relationship_key: str,
        stable_id: str,
        minimum_ms: int,
        maximum_ms: int,
        host: str = "",
        lifecycle_id: str = "",
        ordinal: int = 0,
        sample_key: str = "packet_observation",
        mode_fraction: float = 0.35,
    ) -> timedelta:
        """Return one typed packet-observation gap with microsecond texture.

        The legacy packet helper composed an integer-millisecond relationship
        sample with an independently seeded 37--997 microsecond suffix. One
        runtime-owned triangular draw now preserves that exact inclusive
        support without retaining the millisecond lattice or a second timing
        authority.
        """

        if minimum_ms < 0:
            raise TimingDistributionError("minimum_ms must be non-negative")
        if maximum_ms < minimum_ms:
            raise TimingDistributionError("maximum_ms must not be less than minimum_ms")
        if not 0.0 <= mode_fraction <= 1.0:
            raise TimingDistributionError("mode_fraction must be between zero and one")

        # TimingSampler quantizes continuous distributions to a whole
        # microsecond strictly inside their support. These open bounds therefore
        # produce the former inclusive [min_ms + 37us, max_ms + 997us] range.
        minimum_us = (minimum_ms * 1_000) + 36
        maximum_us = (maximum_ms * 1_000) + 998
        mode_us = minimum_us + ((maximum_us - minimum_us) * mode_fraction)
        return self.runtime.sampler.sample_timedelta(
            TriangularDistribution(
                minimum=float(minimum_us),
                mode=mode_us,
                maximum=float(maximum_us),
            ),
            relationship_key=relationship_key,
            scope=TimingScope(
                stable_id=stable_id,
                host=host,
                source=self.source,
                lifecycle_id=lifecycle_id,
                ordinal=ordinal,
            ),
            sample_key=sample_key,
        )

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
        """Return a signed or unsigned interior truncated-normal sample."""

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
            scope=TimingScope(
                stable_id=stable_id,
                host=host,
                source=self.source,
                lifecycle_id=lifecycle_id,
                ordinal=ordinal,
            ),
            sample_key=sample_key,
        )
        return microseconds / 1_000_000

    def lifetime_seconds(
        self,
        *,
        relationship_key: str,
        stable_id: str,
        minimum: float,
        median: float,
        p95: float,
        maximum: float,
        host: str = "",
        lifecycle_id: str = "",
        ordinal: int = 0,
    ) -> float:
        """Return one bounded heavy-tailed process lifetime without clamp atoms."""

        sigma = max(0.18, math.log(max(p95, median + 1.0) / max(median, 1.0)) / 1.645)
        main = TruncatedLognormalDistribution(
            median=max(1.0, median * 1_000_000),
            sigma=sigma,
            minimum=max(0.0, minimum * 1_000_000),
            maximum=maximum * 1_000_000,
        )
        tail_minimum = max(minimum, min(maximum - 0.000002, p95))
        distribution = main
        if maximum > tail_minimum + 0.000002:
            tail = TruncatedLognormalDistribution(
                median=max(1.0, ((tail_minimum + maximum) / 2) * 1_000_000),
                sigma=max(0.35, sigma),
                minimum=tail_minimum * 1_000_000,
                maximum=maximum * 1_000_000,
            )
            distribution = MixtureDistribution(
                (
                    WeightedDistribution(0.92, main),
                    WeightedDistribution(0.08, tail),
                )
            )
        microseconds = self.runtime.sampler.sample_microseconds(
            distribution,
            relationship_key=relationship_key,
            scope=TimingScope(
                stable_id=stable_id,
                host=host,
                source=self.source,
                lifecycle_id=lifecycle_id,
                ordinal=ordinal,
            ),
            sample_key="lifetime",
        )
        return microseconds / 1_000_000

    def mixture_seconds(
        self,
        *,
        relationship_key: str,
        stable_id: str,
        components: tuple[tuple[float, float, float, float], ...],
        host: str = "",
        lifecycle_id: str = "",
        ordinal: int = 0,
        sample_key: str = "seconds",
    ) -> float:
        """Return one value from weighted right-skew timing families."""

        weighted = []
        for weight, minimum, median, maximum in components:
            if maximum <= minimum:
                component = ConstantDistribution(minimum * 1_000_000)
            else:
                component = TruncatedLognormalDistribution(
                    median=max(1.0, median * 1_000_000),
                    sigma=0.62,
                    minimum=max(0.0, minimum * 1_000_000),
                    maximum=maximum * 1_000_000,
                )
            weighted.append(WeightedDistribution(weight, component))
        distribution = MixtureDistribution(tuple(weighted))
        microseconds = self.runtime.sampler.sample_microseconds(
            distribution,
            relationship_key=relationship_key,
            scope=TimingScope(
                stable_id=stable_id,
                host=host,
                source=self.source,
                lifecycle_id=lifecycle_id,
                ordinal=ordinal,
            ),
            sample_key=sample_key,
        )
        return microseconds / 1_000_000

    def clustered_phase_seconds(
        self,
        *,
        relationship_key: str,
        stable_id: str,
        centers: tuple[float, ...],
        cluster_width: float,
        minimum: float,
        maximum: float,
        cluster_weight: float = 0.7,
        host: str = "",
        lifecycle_id: str = "",
        ordinal: int = 0,
        sample_key: str = "phase",
    ) -> float:
        """Return a clustered phase with a diffuse background component."""

        bounded_centers = tuple(min(maximum, max(minimum, center)) for center in centers)
        if maximum <= minimum or not bounded_centers:
            distribution = ConstantDistribution(minimum * 1_000_000)
        else:
            per_cluster_weight = cluster_weight / len(bounded_centers)
            components: list[WeightedDistribution] = [
                WeightedDistribution(
                    per_cluster_weight,
                    TruncatedNormalDistribution(
                        mean=center * 1_000_000,
                        standard_deviation=max(0.000001, cluster_width / 3) * 1_000_000,
                        minimum=minimum * 1_000_000,
                        maximum=maximum * 1_000_000,
                    ),
                )
                for center in bounded_centers
            ]
            components.append(
                WeightedDistribution(
                    max(0.0, 1.0 - cluster_weight),
                    TriangularDistribution(
                        minimum * 1_000_000,
                        (minimum + (maximum - minimum) * 0.42) * 1_000_000,
                        maximum * 1_000_000,
                    ),
                )
            )
            distribution = MixtureDistribution(tuple(components))
        microseconds = self.runtime.sampler.sample_microseconds(
            distribution,
            relationship_key=relationship_key,
            scope=TimingScope(
                stable_id=stable_id,
                host=host,
                source=self.source,
                lifecycle_id=lifecycle_id,
                ordinal=ordinal,
            ),
            sample_key=sample_key,
        )
        return microseconds / 1_000_000

    def after(
        self,
        anchor: datetime,
        **kwargs: object,
    ) -> datetime:
        """Return an anchor plus a typed right-skew duration."""

        return ensure_utc(anchor) + timedelta(seconds=self.right_skew_seconds(**kwargs))

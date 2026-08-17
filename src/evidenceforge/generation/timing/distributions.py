# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic, config-neutral timing distributions.

The sampler in this module is intentionally stateless. Every draw is derived
from a semantic relationship key and :class:`TimingScope`, so call order,
thread scheduling, and cache eviction cannot change a generated value.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from statistics import NormalDist
from typing import Protocol, TypeAlias

from evidenceforge.utils.rng import (
    DEFAULT_GENERATION_SEED,
    MAX_GENERATION_SEED,
    current_generation_seed,
)

_MAX_QUANTIZATION_ATTEMPTS = 64


class TimingDistributionError(ValueError):
    """A timing distribution is invalid or cannot produce a requested sample."""


def _require_finite(name: str, value: float) -> None:
    """Raise when a distribution parameter is not finite."""

    if not math.isfinite(value):
        raise TimingDistributionError(f"{name} must be finite, got {value!r}")


@dataclass(frozen=True, slots=True)
class ConstantDistribution:
    """A deliberate fixed value, reserved for real protocol or policy constants."""

    value: float

    def __post_init__(self) -> None:
        """Validate the fixed value."""

        _require_finite("value", self.value)


@dataclass(frozen=True, slots=True)
class TriangularDistribution:
    """A bounded triangular distribution with an explicit mode."""

    minimum: float
    mode: float
    maximum: float

    def __post_init__(self) -> None:
        """Validate the support and mode."""

        for name, value in (
            ("minimum", self.minimum),
            ("mode", self.mode),
            ("maximum", self.maximum),
        ):
            _require_finite(name, value)
        if self.maximum <= self.minimum:
            raise TimingDistributionError("maximum must be greater than minimum")
        if not self.minimum <= self.mode <= self.maximum:
            raise TimingDistributionError("mode must fall between minimum and maximum")


@dataclass(frozen=True, slots=True)
class TruncatedNormalDistribution:
    """A normal distribution conditioned on open lower and upper bounds."""

    mean: float
    standard_deviation: float
    minimum: float
    maximum: float

    def __post_init__(self) -> None:
        """Validate the normal parameters and truncation interval."""

        for name, value in (
            ("mean", self.mean),
            ("standard_deviation", self.standard_deviation),
            ("minimum", self.minimum),
            ("maximum", self.maximum),
        ):
            _require_finite(name, value)
        if self.standard_deviation <= 0:
            raise TimingDistributionError("standard_deviation must be greater than zero")
        if self.maximum <= self.minimum:
            raise TimingDistributionError("maximum must be greater than minimum")


@dataclass(frozen=True, slots=True)
class TruncatedLognormalDistribution:
    """A lognormal distribution conditioned on open lower and upper bounds."""

    median: float
    sigma: float
    minimum: float
    maximum: float

    def __post_init__(self) -> None:
        """Validate the lognormal parameters and truncation interval."""

        for name, value in (
            ("median", self.median),
            ("sigma", self.sigma),
            ("minimum", self.minimum),
            ("maximum", self.maximum),
        ):
            _require_finite(name, value)
        if self.median <= 0:
            raise TimingDistributionError("median must be greater than zero")
        if self.sigma <= 0:
            raise TimingDistributionError("sigma must be greater than zero")
        if self.minimum < 0:
            raise TimingDistributionError("minimum must be non-negative")
        if self.maximum <= self.minimum:
            raise TimingDistributionError("maximum must be greater than minimum")


@dataclass(frozen=True, slots=True)
class WeightedDistribution:
    """One weighted component of a mixture distribution."""

    weight: float
    distribution: DistributionSpec

    def __post_init__(self) -> None:
        """Validate the component weight."""

        _require_finite("weight", self.weight)
        if self.weight <= 0:
            raise TimingDistributionError("mixture component weight must be greater than zero")
        validate_distribution_spec(self.distribution)


@dataclass(frozen=True, slots=True)
class MixtureDistribution:
    """A weighted mixture of timing distributions."""

    components: tuple[WeightedDistribution, ...]

    def __post_init__(self) -> None:
        """Normalize and validate the immutable component collection."""

        components = tuple(self.components)
        object.__setattr__(self, "components", components)
        if not components:
            raise TimingDistributionError("mixture must contain at least one component")
        if not all(isinstance(component, WeightedDistribution) for component in components):
            raise TimingDistributionError("mixture components must be WeightedDistribution values")
        total_weight = sum(component.weight for component in components)
        if not math.isfinite(total_weight) or total_weight <= 0:
            raise TimingDistributionError("mixture weights must have a finite positive sum")


DistributionSpec: TypeAlias = (
    ConstantDistribution
    | TriangularDistribution
    | TruncatedNormalDistribution
    | TruncatedLognormalDistribution
    | MixtureDistribution
)

_DISTRIBUTION_TYPES = (
    ConstantDistribution,
    TriangularDistribution,
    TruncatedNormalDistribution,
    TruncatedLognormalDistribution,
    MixtureDistribution,
)


def validate_distribution_spec(distribution: object) -> DistributionSpec:
    """Return a supported immutable distribution or raise an actionable error."""

    if not isinstance(distribution, _DISTRIBUTION_TYPES):
        raise TimingDistributionError(
            f"unsupported timing distribution type: {type(distribution).__name__}"
        )
    return distribution


@dataclass(frozen=True, slots=True)
class TimingScope:
    """Stable semantic identity for one order-independent timing draw."""

    stable_id: str
    host: str = ""
    source: str = ""
    lifecycle_id: str = ""
    ordinal: int = 0

    def __post_init__(self) -> None:
        """Require a durable primary identity and an integral ordinal."""

        if not self.stable_id:
            raise TimingDistributionError("TimingScope.stable_id must not be empty")
        if not isinstance(self.ordinal, int) or isinstance(self.ordinal, bool):
            raise TimingDistributionError("TimingScope.ordinal must be an integer")

    def seed_parts(self) -> tuple[str | int, ...]:
        """Return the unambiguous semantic parts used to seed a draw."""

        return (
            self.stable_id,
            self.host,
            self.source,
            self.lifecycle_id,
            self.ordinal,
        )


class TimingSampleObserver(Protocol):
    """Receive diagnostic sample counts without influencing sampled values."""

    def record_sample(self, relationship_key: str, distribution_kind: str) -> None:
        """Record one completed timing sample."""


@dataclass(frozen=True, slots=True)
class _NumericSample:
    """One raw numeric draw and its selected component support."""

    value: float
    minimum: float | None = None
    maximum: float | None = None
    permits_boundary: bool = False


class TimingSampler:
    """Sample deterministic timing values from immutable distribution specs."""

    def __init__(
        self,
        *,
        namespace: str = "shared-timing-v1",
        observer: TimingSampleObserver | None = None,
        generation_seed: int | None = None,
    ) -> None:
        if not namespace:
            raise TimingDistributionError("sampler namespace must not be empty")
        if generation_seed is None:
            generation_seed = current_generation_seed()
        if not isinstance(generation_seed, int) or not 0 <= generation_seed <= MAX_GENERATION_SEED:
            raise TimingDistributionError(
                f"generation_seed must be an integer between 0 and {MAX_GENERATION_SEED}"
            )
        self._namespace = namespace
        self._observer = observer
        self._generation_seed = generation_seed

    @property
    def namespace(self) -> str:
        """Return the stable seed namespace for this sampler."""

        return self._namespace

    @property
    def generation_seed(self) -> int:
        """Return the immutable generation seed captured by this sampler."""

        return self._generation_seed

    def sample_value(
        self,
        distribution: DistributionSpec,
        *,
        relationship_key: str,
        scope: TimingScope,
        sample_key: str = "value",
    ) -> float:
        """Return one deterministic continuous numeric sample.

        Values are not clamped. Truncated distributions are sampled from their
        conditional CDF, so out-of-range probability does not accumulate at a
        support boundary.
        """

        self._validate_request(distribution, relationship_key, sample_key)
        rng = self._rng(relationship_key, scope, sample_key)
        sample = self._draw(distribution, rng)
        self._record(relationship_key, distribution)
        return sample.value

    def record_logical_sample(
        self,
        distribution: DistributionSpec,
        *,
        relationship_key: str,
    ) -> None:
        """Record one logical draw whose value may come from a deterministic cache.

        Caches may skip numeric recomputation, but diagnostics must describe
        semantic sampling requests rather than cache misses.  This method lets
        a cache owner record that request without consuming RNG state.
        """

        validate_distribution_spec(distribution)
        if not relationship_key:
            raise TimingDistributionError("relationship_key must not be empty")
        self._record(relationship_key, distribution)

    def sample_microseconds(
        self,
        distribution: DistributionSpec,
        *,
        relationship_key: str,
        scope: TimingScope,
        sample_key: str = "value",
    ) -> int:
        """Return one deterministic whole-microsecond sample.

        Continuous draws are re-sampled when microsecond quantization would
        land exactly on an open truncation boundary. This avoids replacing a
        floating-point clamp atom with a timestamp-precision atom.
        """

        self._validate_request(distribution, relationship_key, sample_key)
        rng = self._rng(relationship_key, scope, sample_key)
        for _ in range(_MAX_QUANTIZATION_ATTEMPTS):
            sample = self._draw(distribution, rng)
            value = round(sample.value)
            if sample.permits_boundary or self._strictly_inside(value, sample):
                self._record(relationship_key, distribution)
                return value
        raise TimingDistributionError(
            "distribution has no practically sampleable whole-microsecond value "
            "inside its open bounds"
        )

    def sample_timedelta(
        self,
        distribution: DistributionSpec,
        *,
        relationship_key: str,
        scope: TimingScope,
        sample_key: str = "value",
    ) -> timedelta:
        """Return one deterministic distribution value as a timedelta."""

        microseconds = self.sample_microseconds(
            distribution,
            relationship_key=relationship_key,
            scope=scope,
            sample_key=sample_key,
        )
        return timedelta(microseconds=microseconds)

    def after(
        self,
        anchor: datetime,
        distribution: DistributionSpec,
        *,
        relationship_key: str,
        scope: TimingScope,
        sample_key: str = "value",
    ) -> datetime:
        """Return ``anchor`` plus one deterministic timing delta."""

        return anchor + self.sample_timedelta(
            distribution,
            relationship_key=relationship_key,
            scope=scope,
            sample_key=sample_key,
        )

    def _rng(
        self,
        relationship_key: str,
        scope: TimingScope,
        sample_key: str,
    ) -> random.Random:
        """Create a fresh RNG from an unambiguous semantic seed."""

        seed_material = json.dumps(
            (
                self._namespace,
                relationship_key,
                sample_key,
                *scope.seed_parts(),
            ),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        stable_key = f"timing:{seed_material}"
        if self._generation_seed != DEFAULT_GENERATION_SEED:
            stable_key = f"seed:{self._generation_seed}:{stable_key}"
        seed = int(hashlib.sha256(stable_key.encode()).hexdigest(), 16) % (2**32)
        return random.Random(seed)

    def _draw(self, distribution: DistributionSpec, rng: random.Random) -> _NumericSample:
        """Draw from one validated distribution with the supplied private RNG."""

        if isinstance(distribution, ConstantDistribution):
            return _NumericSample(distribution.value, permits_boundary=True)
        if isinstance(distribution, TriangularDistribution):
            value = self._triangular(distribution, rng)
            return _NumericSample(value, distribution.minimum, distribution.maximum)
        if isinstance(distribution, TruncatedNormalDistribution):
            value = self._truncated_normal(distribution, rng)
            return _NumericSample(value, distribution.minimum, distribution.maximum)
        if isinstance(distribution, TruncatedLognormalDistribution):
            value = self._truncated_lognormal(distribution, rng)
            return _NumericSample(value, distribution.minimum, distribution.maximum)
        if isinstance(distribution, MixtureDistribution):
            component = self._mixture_component(distribution, rng)
            return self._draw(component.distribution, rng)
        raise TimingDistributionError(
            f"unsupported timing distribution type: {type(distribution).__name__}"
        )

    @staticmethod
    def _triangular(
        distribution: TriangularDistribution,
        rng: random.Random,
    ) -> float:
        """Sample an open-support triangle through its inverse CDF."""

        unit = TimingSampler._open_unit(rng)
        width = distribution.maximum - distribution.minimum
        mode_fraction = (distribution.mode - distribution.minimum) / width
        if unit < mode_fraction:
            return distribution.minimum + math.sqrt(
                unit * width * (distribution.mode - distribution.minimum)
            )
        return distribution.maximum - math.sqrt(
            (1.0 - unit) * width * (distribution.maximum - distribution.mode)
        )

    @staticmethod
    def _truncated_normal(
        distribution: TruncatedNormalDistribution,
        rng: random.Random,
    ) -> float:
        """Sample a truncated normal through its conditional inverse CDF."""

        normal = NormalDist(mu=distribution.mean, sigma=distribution.standard_deviation)
        lower_probability = normal.cdf(distribution.minimum)
        upper_probability = normal.cdf(distribution.maximum)
        probability = TimingSampler._conditional_probability(
            lower_probability,
            upper_probability,
            rng,
        )
        value = normal.inv_cdf(probability)
        if not distribution.minimum < value < distribution.maximum:
            raise TimingDistributionError("normal inverse CDF did not produce an interior value")
        return value

    @staticmethod
    def _truncated_lognormal(
        distribution: TruncatedLognormalDistribution,
        rng: random.Random,
    ) -> float:
        """Sample a truncated lognormal through its conditional inverse CDF."""

        log_normal = NormalDist(mu=math.log(distribution.median), sigma=distribution.sigma)
        lower_probability = (
            0.0 if distribution.minimum == 0 else log_normal.cdf(math.log(distribution.minimum))
        )
        upper_probability = log_normal.cdf(math.log(distribution.maximum))
        probability = TimingSampler._conditional_probability(
            lower_probability,
            upper_probability,
            rng,
        )
        value = math.exp(log_normal.inv_cdf(probability))
        if not distribution.minimum < value < distribution.maximum:
            raise TimingDistributionError("lognormal inverse CDF did not produce an interior value")
        return value

    @staticmethod
    def _mixture_component(
        distribution: MixtureDistribution,
        rng: random.Random,
    ) -> WeightedDistribution:
        """Select one component without retaining mutable RNG state."""

        total_weight = sum(component.weight for component in distribution.components)
        target = TimingSampler._open_unit(rng) * total_weight
        cumulative = 0.0
        for component in distribution.components:
            cumulative += component.weight
            if target < cumulative:
                return component
        return distribution.components[-1]

    @staticmethod
    def _conditional_probability(
        lower_probability: float,
        upper_probability: float,
        rng: random.Random,
    ) -> float:
        """Return an open probability inside a truncated CDF interval."""

        if upper_probability <= lower_probability:
            raise TimingDistributionError(
                "truncation interval has no representable probability mass"
            )
        unit = TimingSampler._open_unit(rng)
        probability = lower_probability + unit * (upper_probability - lower_probability)
        if probability <= lower_probability:
            probability = math.nextafter(lower_probability, upper_probability)
        if probability >= upper_probability:
            probability = math.nextafter(upper_probability, lower_probability)
        if not 0.0 < probability < 1.0:
            raise TimingDistributionError(
                "truncation interval has no representable interior probability"
            )
        return probability

    @staticmethod
    def _open_unit(rng: random.Random) -> float:
        """Return a deterministic binary fraction strictly between zero and one."""

        # Fifty-two bits keep both half-step endpoints exactly representable as
        # binary64 values, including the largest draw immediately below one.
        return (rng.getrandbits(52) + 0.5) / 2**52

    @staticmethod
    def _strictly_inside(value: int, sample: _NumericSample) -> bool:
        """Return whether a quantized continuous draw remains inside its support."""

        return bool(
            sample.minimum is not None
            and sample.maximum is not None
            and sample.minimum < value < sample.maximum
        )

    @staticmethod
    def _validate_request(
        distribution: DistributionSpec,
        relationship_key: str,
        sample_key: str,
    ) -> None:
        """Validate one sampling request before constructing its RNG."""

        validate_distribution_spec(distribution)
        if not relationship_key:
            raise TimingDistributionError("relationship_key must not be empty")
        if not sample_key:
            raise TimingDistributionError("sample_key must not be empty")

    def _record(self, relationship_key: str, distribution: DistributionSpec) -> None:
        """Notify the optional audit observer after a completed sample."""

        if self._observer is not None:
            self._observer.record_sample(
                relationship_key,
                self._distribution_kind(distribution),
            )

    @staticmethod
    def _distribution_kind(distribution: DistributionSpec) -> str:
        """Return the stable diagnostic name for a distribution spec."""

        if isinstance(distribution, ConstantDistribution):
            return "constant"
        if isinstance(distribution, TriangularDistribution):
            return "triangular"
        if isinstance(distribution, TruncatedNormalDistribution):
            return "truncated_normal"
        if isinstance(distribution, TruncatedLognormalDistribution):
            return "truncated_lognormal"
        if isinstance(distribution, MixtureDistribution):
            return "mixture"
        raise TimingDistributionError(
            f"unsupported timing distribution type: {type(distribution).__name__}"
        )

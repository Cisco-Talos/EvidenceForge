# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Allocation-free Mac uptime projection from explicit modeled clock facts.

No host clock or hardware API is consulted. Source owners must supply a timebase;
an architecture name alone is not evidence of its tick rate. The current profile
excludes sleep/wake, so elapsed canonical time denotes awake uptime.
"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from evidenceforge.generation.timing.distributions import TimingDistributionError
from evidenceforge.utils.time import ensure_utc


@dataclass(frozen=True, slots=True)
class MachTimebase:
    """Explicit Mach tick-to-nanosecond ratio, as numerator / denominator."""

    numerator: int
    denominator: int

    def __post_init__(self) -> None:
        """Require the positive native unsigned 32-bit ratio components."""
        for value in (self.numerator, self.denominator):
            if type(value) is not int or not 0 < value < 2**32:
                raise TimingDistributionError("Mach timebase requires positive uint32 values")

    def ticks_for_nanoseconds(self, nanoseconds: int) -> int:
        """Project elapsed nanoseconds without floating-point precision loss.

        Round down to the last completed tick and reject native counter overflow.
        """
        if type(nanoseconds) is not int or nanoseconds < 0:
            raise TimingDistributionError("Mach elapsed nanoseconds must be a nonnegative int")
        ticks = nanoseconds * self.denominator // self.numerator
        if ticks >= 2**64:
            raise TimingDistributionError("Mach uptime exceeds the native uint64 tick range")
        return ticks


@dataclass(frozen=True, slots=True)
class MacosBootClock:
    """Immutable boot and timebase facts shared by native source projections.

    This is not a wall-clock model. Endpoint clock offset, drift, observation delay
    and source rendering still belong to the existing timing/observation owners.
    """

    hostname: str
    boot_time: datetime
    boot_uuid: str
    timebase: MachTimebase

    def __post_init__(self) -> None:
        """Reject incomplete facts without filling unknown native values."""
        if type(self.hostname) is not str or not self.hostname.strip():
            raise TimingDistributionError("Mac boot clock requires a modeled hostname")
        if type(self.boot_time) is not datetime or self.boot_time.utcoffset() is None:
            raise TimingDistributionError("Mac boot clock requires an aware boot time")
        if type(self.timebase) is not MachTimebase:
            raise TimingDistributionError("Mac boot clock requires an explicit Mach timebase")
        if type(self.boot_uuid) is not str:
            raise TimingDistributionError("Mac boot clock requires a canonical boot UUID")
        try:
            parsed = UUID(self.boot_uuid)
        except ValueError as error:
            raise TimingDistributionError(
                "Mac boot clock requires a canonical boot UUID"
            ) from error
        if parsed.int == 0 or str(parsed) != self.boot_uuid.lower():
            raise TimingDistributionError("Mac boot clock requires a nonnil canonical boot UUID")
        object.__setattr__(self, "boot_time", ensure_utc(self.boot_time))
        object.__setattr__(self, "boot_uuid", str(parsed).upper())

    def ticks_at(self, canonical_time: datetime) -> int:
        """Return host uptime ticks for an awake canonical occurrence.

        A delayed export must use the occurrence time, not its collection time.
        Values before boot are invalid rather than silently clamped to zero.
        """
        if type(canonical_time) is not datetime or canonical_time.utcoffset() is None:
            raise TimingDistributionError("Mach occurrence time must be timezone-aware")
        elapsed = ensure_utc(canonical_time) - self.boot_time
        elapsed_microseconds = (
            elapsed.days * 86_400 + elapsed.seconds
        ) * 1_000_000 + elapsed.microseconds
        return self.timebase.ticks_for_nanoseconds(elapsed_microseconds * 1_000)

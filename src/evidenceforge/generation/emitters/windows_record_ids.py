# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Source-native Windows EventRecordID sequence modeling."""

import math
import random
from datetime import datetime
from typing import Any

from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc


def coerce_windows_event_id(value: Any) -> int | None:
    """Return a numeric Windows Event ID when raw emitter input is safely parseable.

    Raw scenario events intentionally carry arbitrary emitter fields. Event IDs
    that are malformed should still render as authored, but should not abort
    source-native EventRecordID sequencing.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            return int(stripped, 10)
        except ValueError:
            return None
    return None


def normalize_windows_event_id_value(value: Any) -> Any:
    """Return an EventID value that is safe for Windows XML template helpers.

    Jinja template lookups compare EventID against numeric IDs and use it as a
    dictionary key for source-native metadata. Container values from raw events
    should render as authored text instead of raising unhashable-type errors.
    """
    try:
        hash(value)
    except TypeError:
        return str(value)
    return value


class WindowsRecordIdSequence:
    """Generate one source-native EventRecordID sequence for a host/channel.

    A rendered gap represents records written to the same Windows channel but
    omitted from EvidenceForge's bounded source projection. Hidden records are
    therefore sampled from elapsed time, never independently per visible row.
    """

    def __init__(self, channel: str, host_key: str, host_type: str = ""):
        self.channel = channel.lower()
        self.host_key = host_key or "unknown"
        self.host_type = host_type.lower()
        self._host_class = self._resolve_host_class()
        self._rng = random.Random(_stable_seed(f"windows_record_id:{self.channel}:{self.host_key}"))
        self.current = self._initial_value()
        self._last_timestamp: datetime | None = None
        self._background_rate = self._host_background_rate()
        self._peak_background_rate = self._host_peak_background_rate()

    def next(self, timestamp: datetime | None = None, event_id: int | None = None) -> int:
        """Return the next EventRecordID for a visible event."""
        if self.channel == "security" and event_id == 1102:
            self.current = 1
            self._last_timestamp = (
                ensure_utc(timestamp) if isinstance(timestamp, datetime) else None
            )
            return self.current
        hidden = self._hidden_events_since_last_visible(timestamp)
        self.current += 1 + hidden
        if isinstance(timestamp, datetime):
            self._last_timestamp = ensure_utc(timestamp)
        return self.current

    def _initial_value(self) -> int:
        if self.channel == "security":
            if self._host_class == "domain_controller":
                return self._rng.randint(6_000_000, 35_000_000)
            if self._host_class == "server":
                return self._rng.randint(180_000, 4_500_000)
            return self._rng.randint(25_000, 950_000)
        if self._host_class == "domain_controller":
            return self._rng.randint(350_000, 5_500_000)
        if self._host_class == "server":
            return self._rng.randint(80_000, 1_800_000)
        return self._rng.randint(15_000, 750_000)

    def _resolve_host_class(self) -> str:
        """Resolve typed host capability, with a compatibility fallback for raw rows."""
        if self.host_type == "domain_controller":
            return "domain_controller"
        if self.host_type == "server":
            return "server"
        if self.host_type == "workstation":
            return "workstation"

        host_lower = self.host_key.lower()
        if "dc" in host_lower:
            return "domain_controller"
        if any(
            token in host_lower for token in ("srv", "server", "web", "file", "db", "mail", "exch")
        ):
            return "server"
        return "workstation"

    def _host_background_rate(self) -> float:
        """Return hidden channel events per second for this host/source."""
        host_jitter = 0.75 + (self._rng.random() * 0.75)
        if self.channel == "security":
            if self._host_class == "domain_controller":
                return self._rng.uniform(0.06, 0.42) * host_jitter
            if self._host_class == "server":
                return self._rng.uniform(0.015, 0.16) * host_jitter
            return self._rng.uniform(0.004, 0.055) * host_jitter
        if self._host_class == "domain_controller":
            return self._rng.uniform(0.01, 0.095) * host_jitter
        if self._host_class == "server":
            return self._rng.uniform(0.005, 0.06) * host_jitter
        return self._rng.uniform(0.0015, 0.035) * host_jitter

    def _host_peak_background_rate(self) -> float:
        """Return a conservative ceiling for omitted records per second.

        The ceiling is a safety bound, not the expected rate. It prevents a
        random draw from implying an impossible millisecond-scale channel burst
        while still allowing short, high-volume intervals on domain controllers.
        """
        if self.channel == "security":
            if self._host_class == "domain_controller":
                return 240.0
            if self._host_class == "server":
                return 120.0
            return 60.0
        if self._host_class == "domain_controller":
            return 160.0
        if self._host_class == "server":
            return 100.0
        return 60.0

    def _hidden_events_since_last_visible(self, timestamp: datetime | None) -> int:
        if not isinstance(timestamp, datetime) or self._last_timestamp is None:
            return 0
        elapsed = max(0.0, (ensure_utc(timestamp) - self._last_timestamp).total_seconds())
        if elapsed <= 0.0:
            return 0
        expected = elapsed * self._background_rate
        hidden = self._sample_poisson(expected)
        maximum = math.ceil(elapsed * self._peak_background_rate)
        return min(hidden, maximum)

    def _sample_poisson(self, expected: float) -> int:
        """Sample a Poisson-like count in bounded time for long scenarios."""
        if expected <= 0.0:
            return 0
        if expected >= 30.0:
            # The normal approximation preserves Poisson mean/variance while
            # keeping multi-day gaps O(1) instead of iterating per hidden row.
            return max(0, round(self._rng.gauss(expected, math.sqrt(expected))))

        threshold = math.exp(-expected)
        product = 1.0
        samples = 0
        while product > threshold:
            samples += 1
            product *= self._rng.random()
        return samples - 1

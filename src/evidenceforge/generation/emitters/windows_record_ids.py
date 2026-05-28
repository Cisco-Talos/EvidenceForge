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

import random
from datetime import datetime

from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc


class WindowsRecordIdSequence:
    """Generate monotonic EventRecordIDs with organic filtered-channel gaps."""

    def __init__(self, channel: str, host_key: str):
        self.channel = channel.lower()
        self.host_key = host_key or "unknown"
        self._rng = random.Random(_stable_seed(f"windows_record_id:{self.channel}:{self.host_key}"))
        self.current = self._initial_value()
        self._last_timestamp: datetime | None = None
        self._background_rate = self._host_background_rate()

    def next(self, timestamp: datetime | None = None, event_id: int | None = None) -> int:
        """Return the next EventRecordID for a visible event."""
        hidden = self._hidden_events_since_last_visible(timestamp)
        hidden += self._sample_filtered_channel_gap(event_id)
        self.current += 1 + hidden
        if isinstance(timestamp, datetime):
            self._last_timestamp = ensure_utc(timestamp)
        return self.current

    def _initial_value(self) -> int:
        host_lower = self.host_key.lower()
        if self.channel == "security":
            if "dc" in host_lower:
                return self._rng.randint(6_000_000, 35_000_000)
            if any(
                token in host_lower
                for token in ("srv", "server", "web", "file", "db", "mail", "exch")
            ):
                return self._rng.randint(180_000, 4_500_000)
            return self._rng.randint(25_000, 950_000)
        if "dc" in host_lower:
            return self._rng.randint(350_000, 5_500_000)
        if any(
            token in host_lower for token in ("srv", "server", "web", "file", "db", "mail", "exch")
        ):
            return self._rng.randint(80_000, 1_800_000)
        return self._rng.randint(15_000, 750_000)

    def _host_background_rate(self) -> float:
        """Return hidden channel events per second for this host/source."""
        host_lower = self.host_key.lower()
        host_jitter = 0.75 + (self._rng.random() * 0.75)
        if self.channel == "security":
            if "dc" in host_lower:
                return self._rng.uniform(0.06, 0.42) * host_jitter
            if any(
                token in host_lower
                for token in ("srv", "server", "web", "file", "db", "mail", "exch")
            ):
                return self._rng.uniform(0.015, 0.16) * host_jitter
            return self._rng.uniform(0.004, 0.055) * host_jitter
        if "dc" in host_lower:
            return self._rng.uniform(0.01, 0.095) * host_jitter
        if any(
            token in host_lower for token in ("srv", "server", "web", "file", "db", "mail", "exch")
        ):
            return self._rng.uniform(0.005, 0.06) * host_jitter
        return self._rng.uniform(0.0015, 0.035) * host_jitter

    def _hidden_events_since_last_visible(self, timestamp: datetime | None) -> int:
        if not isinstance(timestamp, datetime) or self._last_timestamp is None:
            return 0
        elapsed = max(0.0, (ensure_utc(timestamp) - self._last_timestamp).total_seconds())
        expected = elapsed * self._background_rate
        hidden = int(expected)
        if self._rng.random() < expected - hidden:
            hidden += 1
        return hidden

    def _sample_filtered_channel_gap(self, event_id: int | None) -> int:
        """Sample hidden records from unrendered provider/channel activity."""
        if self.channel == "security":
            return self._sample_security_gap(event_id)
        return self._sample_sysmon_gap(event_id)

    def _sample_security_gap(self, event_id: int | None) -> int:
        roll = self._rng.random()
        if event_id in {5156, 4768, 4769, 4770, 4771}:
            roll *= 0.82
        if roll < 0.006:
            return self._rng.randint(900, 18_000)
        if roll < 0.035:
            return self._rng.randint(120, 900)
        if roll < 0.12:
            return self._rng.randint(17, 160)
        if roll < 0.34:
            return self._rng.randint(1, 32)
        return 0

    def _sample_sysmon_gap(self, event_id: int | None) -> int:
        roll = self._rng.random()
        if event_id in {3, 7, 22}:
            roll *= 0.9
        if roll < 0.008:
            return self._rng.randint(650, 7_500)
        if roll < 0.045:
            return self._rng.randint(130, 950)
        if roll < 0.16:
            return self._rng.randint(21, 180)
        if roll < 0.40:
            return self._rng.randint(1, 36)
        return 0

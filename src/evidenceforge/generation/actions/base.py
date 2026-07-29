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

"""Base types for action bundles.

Action bundles model real-world activities above individual SecurityEvents. A
bundle may emit multiple canonical events while owning lifecycle, timing,
observation, and durable identity constraints for the activity as a whole.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ActionAnchor:
    """Stable identifier for a modeled action bundle."""

    family: str
    stable_id: str
    source: str = ""


class ActionBundle(Protocol):
    """Protocol implemented by executable action bundles."""

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""
        ...

    def execute(self) -> str:
        """Expand and dispatch canonical evidence for this action."""
        ...


def source_observation_delay_difference(
    executor: object,
    *,
    earlier_source: str,
    later_source: str,
) -> timedelta:
    """Return a safe cross-source delay budget exposed by the active dispatcher."""

    dispatcher = getattr(executor, "dispatcher", None)
    policy = getattr(dispatcher, "observation_policy", None)
    resolver = getattr(policy, "maximum_delay_difference", None)
    if not callable(resolver):
        return timedelta(0)
    result = resolver(earlier_source, later_source)
    return max(timedelta(0), result) if isinstance(result, timedelta) else timedelta(0)


def endpoint_clock_difference(
    executor: object,
    *,
    earlier_host: str,
    earlier_os: str,
    later_host: str,
    later_os: str,
    timestamp: datetime,
) -> timedelta:
    """Return positive rendered clock lead of an earlier endpoint over a later one."""

    planner = getattr(executor, "_source_timing_planner", None)
    resolver = getattr(planner, "endpoint_clock_adjustment_for_host", None)
    if not callable(resolver):
        return timedelta(0)
    earlier = resolver(
        hostname=earlier_host,
        os_category=earlier_os,
        timestamp=timestamp,
    )
    later = resolver(
        hostname=later_host,
        os_category=later_os,
        timestamp=timestamp,
    )
    if not isinstance(earlier, timedelta) or not isinstance(later, timedelta):
        return timedelta(0)
    return max(timedelta(0), earlier - later)

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

"""DNS lookup action bundle."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.utils.rng import _stable_seed


@dataclass(frozen=True, slots=True)
class DnsLookupRequest:
    """Intent for one automatic DNS lookup before a network action."""

    src_ip: str
    dst_ip: str
    time: datetime
    hostname: str | None = None
    force_address: bool = False
    bypass_cache: bool = False
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:dns_lookup:"
            f"{self.src_ip}:{self.dst_ip}:{self.time.isoformat()}:"
            f"{self.hostname or ''}:{self.force_address}:{self.bypass_cache}:{self.source}"
        )
        return f"dns-lookup-{seed:016x}"


class DnsLookupExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    def _execute_dns_lookup_bundle(self, request: DnsLookupRequest) -> None:
        """Expand one DNS lookup request into canonical evidence."""
        ...


class DnsLookupActionBundle:
    """Expand one automatic DNS lookup into resolver evidence."""

    def __init__(self, executor: DnsLookupExecutor, request: DnsLookupRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="dns_lookup",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit DNS connection, DNS answer, and companion resolver evidence."""

        self._executor._execute_dns_lookup_bundle(self._request)

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

"""Expansion rule base class and concrete rule implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evidenceforge.generation.causal.engine import ExpandedEvent, ExpansionContext


@dataclass
class ExpansionRule(ABC):
    """Base class for causal expansion rules.

    Each rule checks whether it applies to a given event type and context,
    then returns zero or more expanded events to emit alongside the trigger.

    Attributes:
        name: Short identifier (e.g., "dns_before_connection").
        description: Human-readable explanation.
        priority: Lower values run first. Used to order rule evaluation.
    """

    name: str = ""
    description: str = ""
    priority: int = 100

    @abstractmethod
    def matches(self, event_type: str, ctx: ExpansionContext) -> bool:
        """Return True if this rule should fire for the given event."""

    @abstractmethod
    def expand(self, event_type: str, ctx: ExpansionContext) -> list[ExpandedEvent]:
        """Return prerequisite/consequent events to emit."""


@dataclass
class DnsBeforeConnection(ExpansionRule):
    """Emit a DNS lookup before TCP connections to named hosts.

    Reproduces the logic from ActivityGenerator._emit_dns_lookup(), including
    DNS caching, SERVFAIL probability, multi-answer CDN responses, NXDOMAIN
    companion queries, and varied query types (A, AAAA, PTR, SRV, MX).
    """

    name: str = field(default="dns_before_connection")
    description: str = field(default="Emit DNS query before TCP connections to named hosts")
    priority: int = field(default=10)

    def matches(self, event_type: str, ctx: ExpansionContext) -> bool:
        return (
            event_type == "connection"
            and ctx.protocol == "tcp"
            and ctx.dst_port not in (53,)
            and ctx.dst_ip is not None
        )

    def expand(self, event_type: str, ctx: ExpansionContext) -> list[ExpandedEvent]:
        from evidenceforge.generation.causal.engine import ExpandedEvent
        from evidenceforge.generation.causal.timing import TimingSpec

        return [
            ExpandedEvent(
                method="_emit_dns_lookup",
                kwargs={
                    "src_ip": ctx.src_ip,
                    "dst_ip": ctx.dst_ip,
                },
                timing=TimingSpec(min_ms=0, max_ms=0, position="before"),
                description="DNS lookup for connection destination",
            )
        ]

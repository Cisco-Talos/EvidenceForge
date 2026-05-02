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

"""Causal expansion engine and supporting data structures."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from evidenceforge.generation.causal.timing import TimingSpec

if TYPE_CHECKING:
    from evidenceforge.generation.causal.rules import ExpansionRule

logger = logging.getLogger(__name__)


@dataclass
class ExpansionContext:
    """All state available to expansion rules when deciding whether to fire.

    Carries both the event parameters being expanded and engine-level state
    needed for caching/dedup decisions.
    """

    # Event parameters
    event_type: str
    timestamp: datetime
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    service: str | None = None
    logon_type: int | None = None
    auth_package: str | None = None
    command_line: str | None = None
    process_name: str | None = None
    os_category: str | None = None
    source_system: Any = None
    target_system: Any = None
    actor: Any = None

    # Hostname for DNS/SNI consistency (domain-first selection)
    hostname: str | None = None

    # Process/thread fields (for create_remote_thread, process_access)
    source_pid: int | None = None
    source_image: str | None = None
    target_pid: int | None = None
    target_image: str | None = None
    logon_id: str | None = None

    # Supplementary event dedup: event types explicitly declared in the
    # storyline step, so the engine skips auto-generating them.
    skip_types: set[str] = field(default_factory=set)

    # Engine state for caching/dedup
    dns_cache: dict[tuple[str, str], float] = field(default_factory=dict)
    kerberos_cache: dict[str, float] = field(default_factory=dict)
    dns_server_ips: list[str] = field(default_factory=lambda: ["10.0.0.1"])
    dc_hostnames: list[str] = field(default_factory=list)
    dc_systems: list[Any] = field(default_factory=list)
    ad_domain: str = "corp.local"
    sid_registry: dict[str, str] = field(default_factory=dict)
    created_account_sids: dict[str, str] = field(default_factory=dict)


@dataclass
class ExpandedEvent:
    """An event to emit as part of causal expansion.

    Specifies which ActivityGenerator method to call, with what arguments,
    and when relative to the triggering event.
    """

    method: str
    kwargs: dict[str, Any]
    timing: TimingSpec
    description: str = ""


class CausalExpansionEngine:
    """Expands event specs into causally-complete event sequences.

    Evaluates all registered rules against the event type and context,
    collects expanded events, and returns them in dependency order
    (before-events first, sorted by offset).
    """

    def __init__(self, rules: list[ExpansionRule] | None = None) -> None:
        from evidenceforge.generation.causal.registry import default_rules

        self._rules = sorted(
            rules if rules is not None else default_rules(), key=lambda r: r.priority
        )

    def expand(self, event_type: str, ctx: ExpansionContext) -> list[ExpandedEvent]:
        """Run all matching rules and return ordered expanded events.

        Args:
            event_type: The event type being generated (e.g., "connection").
            ctx: Expansion context with event params and engine state.

        Returns:
            List of ExpandedEvent objects, ordered: before-events (largest
            offset first) then after-events (smallest offset first).
        """
        if event_type == "raw":
            return []

        expanded: list[ExpandedEvent] = []
        for rule in self._rules:
            try:
                if rule.matches(event_type, ctx):
                    expanded.extend(rule.expand(event_type, ctx))
            except Exception:
                logger.exception("Expansion rule %s failed", rule.name)

        return self._resolve_ordering(expanded)

    @staticmethod
    def _resolve_ordering(events: list[ExpandedEvent]) -> list[ExpandedEvent]:
        """Sort expanded events: before-events (earliest first), then after-events."""
        before = [e for e in events if e.timing.position == "before"]
        after = [e for e in events if e.timing.position == "after"]
        # Before events: largest offset = earliest timestamp, so sort descending
        before.sort(key=lambda e: -e.timing.max_ms)
        # After events: smallest offset = closest to trigger, so sort ascending
        after.sort(key=lambda e: e.timing.min_ms)
        return before + after

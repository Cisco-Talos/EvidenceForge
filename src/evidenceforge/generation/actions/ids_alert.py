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

"""IDS alert action bundle."""

from __future__ import annotations

import random
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from evidenceforge.events.contexts import DnsContext, IdsContext
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.utils.rng import _stable_seed

DnsContextFactory = Callable[..., DnsContext | None]


def _signature_value(signature: Mapping[str, Any], name: str, default: Any = "") -> Any:
    """Return a deterministic printable signature value."""

    value = signature.get(name, default)
    if value is None:
        return ""
    if isinstance(value, list | tuple | set):
        return ",".join(str(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class IdsAlertRequest:
    """Intent for one IDS alert attached to a canonical network occurrence."""

    signature: Mapping[str, Any]
    time: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    rng: random.Random
    source: str = "generator"
    direction: str = ""
    ad_domain: str = "corp.local"
    dns_server_ip: str | None = None
    include_dns_payload: bool = False
    dns_context_factory: DnsContextFactory | None = None

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:ids_alert:"
            f"{self.src_ip}:{self.dst_ip}:{self.dst_port}:{self.proto}:"
            f"{self.direction}:{self.time.isoformat()}:{self.source}:"
            f"{_signature_value(self.signature, 'gid', 1)}:"
            f"{_signature_value(self.signature, 'sid')}:"
            f"{_signature_value(self.signature, 'rev', 1)}:"
            f"{_signature_value(self.signature, 'message')}"
        )
        return f"ids-alert-{seed:016x}"


@dataclass(frozen=True, slots=True)
class IdsAlertResult:
    """Canonical context payloads produced by an IDS alert bundle."""

    ids: IdsContext
    dns: DnsContext | None = None


@dataclass(frozen=True, slots=True)
class IdsAlertActionBundle:
    """Build canonical IDS evidence context from a data-driven signature."""

    request: IdsAlertRequest

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="ids_alert",
            stable_id=self.request.stable_id,
            source=self.request.source,
        )

    def execute_with_result(self) -> IdsAlertResult:
        """Return IDS context plus optional signature-owned DNS context."""

        signature = dict(self.request.signature)
        ids = IdsContext(
            sid=int(signature["sid"]),
            rev=int(signature.get("rev", 1)),
            message=str(signature["message"]),
            classification=str(signature.get("classification", "misc-activity")),
            priority=int(signature.get("priority", 2)),
            gid=int(signature.get("gid", 1)),
        )
        dns = None
        if (
            self.request.include_dns_payload
            and self.request.dns_context_factory is not None
            and self.request.dns_server_ip
        ):
            dns = self.request.dns_context_factory(
                signature,
                self.request.rng,
                ad_domain=self.request.ad_domain,
                dns_server_ip=self.request.dns_server_ip,
            )
        return IdsAlertResult(ids=ids, dns=dns)

    def execute(self) -> IdsContext:
        """Return the canonical IDS context."""

        return self.execute_with_result().ids

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
from typing import Any, Literal

from evidenceforge.config.schemas import IdsSignaturePredicateSpec
from evidenceforge.events.contexts import (
    DnsContext,
    IdsAlertPlan,
    IdsAlertPolicyContext,
    IdsDetectionFilterContext,
    IdsEventFilterContext,
)
from evidenceforge.events.network import NetworkTransactionPlan, SignaturePredicate
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.activity.ids_signatures import effective_alert_policy
from evidenceforge.models.ids import IdsAlertPolicyOverride, IdsAlertPolicySpec
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
    policy: IdsAlertPolicyOverride | None = None
    predicate: SignaturePredicate | None = None
    origin: Literal["built_in", "authored_attachment"] = "built_in"

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
            f"{_signature_value(self.signature, 'message')}:"
            f"{self.predicate!r}"
        )
        return f"ids-alert-{seed:016x}"


@dataclass(frozen=True, slots=True)
class IdsAlertResult:
    """Canonical context payloads produced by an IDS alert bundle."""

    alert: IdsAlertPlan
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
        policy = self._effective_policy(signature)
        alert = IdsAlertPlan(
            sid=int(signature["sid"]),
            rev=int(signature.get("rev", 1)),
            message=str(signature["message"]),
            classification=str(signature.get("classification", "misc-activity")),
            priority=int(signature.get("priority", 2)),
            gid=int(signature.get("gid", 1)),
            policy=self._policy_context(policy),
            predicate=self.request.predicate
            or _predicate_from_signature(signature, self.request.proto, self.request.dst_port),
            origin=self.request.origin,
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
        return IdsAlertResult(alert=alert, dns=dns)

    def _effective_policy(self, signature: Mapping[str, Any]) -> IdsAlertPolicySpec | None:
        """Resolve scenario replacement policy over the signature default."""

        return effective_alert_policy(dict(signature), self.request.policy)

    @staticmethod
    def _policy_context(policy: IdsAlertPolicySpec | None) -> IdsAlertPolicyContext | None:
        """Convert validated configuration into canonical immutable-style context."""

        if policy is None:
            return None
        detection = policy.detection_filter
        event_filter = policy.event_filter
        return IdsAlertPolicyContext(
            detection_filter=(
                None
                if detection is None
                else IdsDetectionFilterContext(
                    track=detection.track,
                    count=detection.count,
                    seconds=detection.seconds,
                )
            ),
            event_filter=(
                None
                if event_filter is None
                else IdsEventFilterContext(
                    type=event_filter.type,
                    track=event_filter.track,
                    count=event_filter.count,
                    seconds=event_filter.seconds,
                )
            ),
        )

    def execute(self) -> IdsAlertPlan:
        """Return the canonical IDS context."""

        return self.execute_with_result().alert


def _predicate_from_signature(
    signature: Mapping[str, Any],
    request_protocol: str,
    request_destination_port: int,
) -> SignaturePredicate:
    """Build one immutable predicate from validated signature metadata."""

    configured = signature.get("predicate") or {}
    if not isinstance(configured, Mapping):
        raise ValueError("IDS signature predicate must be a mapping")
    predicate_data = dict(configured)
    if "inspection" not in predicate_data and signature.get("inspection") is not None:
        predicate_data["inspection"] = signature["inspection"]
    spec = IdsSignaturePredicateSpec.model_validate(predicate_data)
    protocol = str(signature.get("proto") or request_protocol).lower()
    destination_port = (
        spec.destination_port
        if spec.destination_port is not None
        else int(signature.get("dst_port", request_destination_port))
    )
    return SignaturePredicate(
        transport_protocol=protocol,
        destination_port=destination_port,
        phase=spec.phase,
        payload_direction=spec.payload_direction,
        minimum_payload_bytes=spec.minimum_payload_bytes,
        requires_response=spec.requires_response,
        application_protocol=spec.application_protocol,
        inspection=spec.inspection,
        http_methods=tuple(spec.http_methods),
        http_statuses=tuple(spec.http_statuses),
        requires_http_body=spec.requires_http_body,
        file_mime_types=tuple(spec.file_mime_types),
        semantic_claim=spec.semantic_claim,
    )


def ids_alert_matches_transaction(
    alert: IdsAlertPlan,
    transaction: NetworkTransactionPlan,
    *,
    http: Any = None,
    dns: Any = None,
    ssl: Any = None,
    file_transfers: tuple[Any, ...] = (),
) -> bool:
    """Return whether a planned IDS alert is possible for canonical network truth."""

    predicate = alert.predicate
    if predicate is None:
        return True
    if predicate.transport_protocol != transaction.protocol.lower():
        return False
    if predicate.destination_port not in {0, transaction.dst_port}:
        return False

    orig_payload = transaction.traffic.orig.payload_bytes
    resp_payload = transaction.traffic.resp.payload_bytes
    has_response = transaction.traffic.resp.packets > 0 or resp_payload > 0
    failed_before_application = transaction.conn_state in {"S0", "REJ", "S1", "SH", "SHR"}
    if predicate.phase == "established" and failed_before_application:
        return False
    if predicate.phase == "application" and (
        failed_before_application or orig_payload + resp_payload <= 0
    ):
        return False
    if predicate.phase == "response" and not has_response:
        return False
    if predicate.requires_response and not has_response:
        return False

    directional_payload = {
        "none": 0,
        "orig": orig_payload,
        "resp": resp_payload,
        "either": orig_payload + resp_payload,
    }[predicate.payload_direction]
    if directional_payload < predicate.minimum_payload_bytes:
        return False

    if predicate.application_protocol == "http" and http is None:
        return False
    if predicate.application_protocol == "dns" and dns is None:
        return False
    if predicate.application_protocol == "tls" and ssl is None:
        return False
    if predicate.application_protocol not in {None, "http", "dns", "tls"} and (
        transaction.service.lower() != predicate.application_protocol
    ):
        return False

    service = transaction.service.lower()
    if predicate.inspection == "payload_cleartext" and service in {"ssl", "tls"}:
        return False
    if predicate.inspection == "payload_decrypted" and not (
        service in {"ssl", "tls"} and http is not None
    ):
        return False

    if predicate.http_methods and (
        http is None or str(http.method).upper() not in predicate.http_methods
    ):
        return False
    if predicate.http_statuses and (
        http is None or int(http.status_code) not in predicate.http_statuses
    ):
        return False
    if predicate.requires_http_body and (http is None or int(http.request_body_len or 0) <= 0):
        return False
    if predicate.semantic_claim == "dns_query" and dns is None:
        return False
    if predicate.semantic_claim == "dns_response" and (dns is None or not has_response):
        return False
    if predicate.semantic_claim == "file_content":
        eligible_files = tuple(
            candidate
            for candidate in file_transfers
            if predicate.payload_direction != "resp" or not bool(candidate.is_orig)
        )
        if not eligible_files:
            return False
        if predicate.file_mime_types and not any(
            str(candidate.mime_type).lower() in predicate.file_mime_types
            for candidate in eligible_files
        ):
            return False
    return True


def normalize_ids_alerts(alerts: list[IdsAlertPlan]) -> tuple[IdsAlertPlan, ...]:
    """Return one deterministic collection with authored attachments taking precedence."""

    authored_keys = {
        (alert.gid, alert.sid) for alert in alerts if alert.origin == "authored_attachment"
    }
    normalized: list[IdsAlertPlan] = []
    seen: set[tuple[int, int]] = set()
    ordered = [
        *(
            alert
            for alert in alerts
            if alert.origin == "built_in" and (alert.gid, alert.sid) not in authored_keys
        ),
        *(alert for alert in alerts if alert.origin == "authored_attachment"),
    ]
    for alert in ordered:
        key = (alert.gid, alert.sid)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(alert)
    return tuple(normalized)

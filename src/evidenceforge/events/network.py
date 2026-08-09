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

"""Immutable canonical network transaction and traffic-accounting types."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

NetworkTransactionOutcome = Literal["success", "failure", "denied"]
PayloadDirection = Literal["none", "orig", "resp", "either"]
TransportPhase = Literal["attempt", "established", "application", "response"]
InspectionCapability = Literal["metadata", "payload_cleartext", "payload_decrypted"]
SemanticClaim = Literal[
    "flow_metadata",
    "scan",
    "handshake",
    "request_content",
    "response_content",
    "upload_request",
    "dns_query",
    "dns_response",
    "file_content",
]


@dataclass(frozen=True, slots=True)
class SignaturePredicate:
    """Canonical preconditions for attaching one IDS signature to a transport."""

    transport_protocol: str
    destination_port: int
    phase: TransportPhase = "attempt"
    payload_direction: PayloadDirection = "none"
    minimum_payload_bytes: int = 0
    requires_response: bool = False
    application_protocol: str | None = None
    inspection: InspectionCapability = "metadata"
    http_methods: tuple[str, ...] = ()
    http_statuses: tuple[int, ...] = ()
    requires_http_body: bool = False
    semantic_claim: SemanticClaim = "flow_metadata"

    def __post_init__(self) -> None:
        """Reject internally contradictory signature requirements."""

        if self.transport_protocol not in {"tcp", "udp", "icmp"}:
            raise ValueError("IDS predicates require tcp, udp, or icmp transport")
        if self.destination_port < 0 or self.destination_port > 65535:
            raise ValueError("IDS predicate destination_port must be between 0 and 65535")
        if self.minimum_payload_bytes < 0:
            raise ValueError("IDS predicate minimum_payload_bytes cannot be negative")
        if self.minimum_payload_bytes and self.payload_direction == "none":
            raise ValueError("IDS payload thresholds require a payload direction")
        if (self.http_methods or self.http_statuses or self.requires_http_body) and (
            self.application_protocol != "http"
        ):
            raise ValueError("HTTP-specific IDS predicates require application_protocol='http'")
        if self.requires_http_body and self.payload_direction not in {"orig", "either"}:
            raise ValueError("HTTP request bodies require orig/either payload direction")


@dataclass(frozen=True, slots=True)
class DirectionalTrafficLedger:
    """Canonical traffic accounting for one direction of a connection."""

    payload_bytes: int = 0
    packets: int = 0
    ip_bytes: int = 0

    def __post_init__(self) -> None:
        """Reject negative or internally impossible accounting."""

        if self.payload_bytes < 0 or self.packets < 0 or self.ip_bytes < 0:
            raise ValueError("Network traffic accounting values must be non-negative")
        if self.ip_bytes < self.payload_bytes:
            raise ValueError("IP byte accounting cannot be smaller than payload bytes")
        if self.packets == 0 and self.ip_bytes > 0:
            raise ValueError("IP byte accounting requires at least one observed packet")

    def accumulate(self, other: DirectionalTrafficLedger) -> DirectionalTrafficLedger:
        """Return cumulative accounting without mutating either ledger."""

        return DirectionalTrafficLedger(
            payload_bytes=self.payload_bytes + other.payload_bytes,
            packets=self.packets + other.packets,
            ip_bytes=self.ip_bytes + other.ip_bytes,
        )


@dataclass(frozen=True, slots=True)
class NetworkTrafficLedger:
    """Canonical bidirectional traffic accounting for one transaction."""

    orig: DirectionalTrafficLedger = DirectionalTrafficLedger()
    resp: DirectionalTrafficLedger = DirectionalTrafficLedger()
    missed_orig_bytes: int = 0
    missed_resp_bytes: int = 0

    def __post_init__(self) -> None:
        """Reject invalid capture-loss accounting."""

        if self.missed_orig_bytes < 0 or self.missed_resp_bytes < 0:
            raise ValueError("Missed-byte accounting must be non-negative")

    @property
    def missed_bytes(self) -> int:
        """Return total source-observed missed payload bytes."""

        return self.missed_orig_bytes + self.missed_resp_bytes

    def accumulate(self, other: NetworkTrafficLedger) -> NetworkTrafficLedger:
        """Return cumulative accounting for a persistent transport."""

        return NetworkTrafficLedger(
            orig=self.orig.accumulate(other.orig),
            resp=self.resp.accumulate(other.resp),
            missed_orig_bytes=self.missed_orig_bytes + other.missed_orig_bytes,
            missed_resp_bytes=self.missed_resp_bytes + other.missed_resp_bytes,
        )


@dataclass(frozen=True, slots=True)
class NetworkTuple:
    """One sensor-visible network five-tuple."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

    def __post_init__(self) -> None:
        """Reject invalid ports at the observation boundary."""

        if self.src_port < 0 or self.dst_port < 0:
            raise ValueError("Observed network tuple ports must be non-negative")


@dataclass(frozen=True, slots=True)
class NatSensorObservation:
    """Source-local view and lifetime of one NAT translation."""

    nat_type: Literal["dynamic_pat", "static"]
    direction: Literal["source", "destination"]
    local_ip: str
    local_port: int
    global_ip: str
    global_port: int
    built_time: datetime
    teardown_time: datetime | None

    def __post_init__(self) -> None:
        """Reject incomplete address views and impossible translation lifetimes."""

        if not self.local_ip or not self.global_ip:
            raise ValueError("NAT observations require local and global addresses")
        if not 0 <= self.local_port <= 65535 or not 0 <= self.global_port <= 65535:
            raise ValueError("NAT observation ports must be between 0 and 65535")
        if self.teardown_time is not None and self.teardown_time < self.built_time:
            raise ValueError("NAT teardown cannot precede translation creation")


@dataclass(frozen=True, slots=True)
class FileSensorObservation:
    """Frozen source-local completeness for one canonical transferred object."""

    canonical_id: str
    seen_bytes: int
    total_bytes: int | None
    missing_bytes: int
    analyzers_visible: bool

    def __post_init__(self) -> None:
        """Reject impossible file-observation accounting."""

        if not self.canonical_id:
            raise ValueError("File observations require a canonical file ID")
        if self.seen_bytes < 0 or self.missing_bytes < 0:
            raise ValueError("File observation byte counts must be non-negative")
        if self.total_bytes is not None:
            if self.total_bytes < 0:
                raise ValueError("File observation total bytes must be non-negative")
            if self.seen_bytes + self.missing_bytes < self.total_bytes:
                raise ValueError("File observations must account for the complete canonical file")


@dataclass(frozen=True, slots=True)
class NetworkSensorObservation:
    """Frozen view of one canonical transaction at one network sensor."""

    sensor_identity: str
    path_role: str
    capture_profile: str
    tuple_view: NetworkTuple
    connection_uid: str
    connection_ids: tuple[tuple[str, str], ...]
    file_ids: tuple[tuple[str, str], ...]
    local_orig: bool
    local_resp: bool
    observed_start_time: datetime
    observed_close_time: datetime | None
    traffic: NetworkTrafficLedger
    visible_formats: frozenset[str]
    history: str = ""
    file_observations: tuple[FileSensorObservation, ...] = ()
    http_request_body_len: int | None = None
    http_response_body_len: int | None = None
    firewall_teardown_reason: str = ""
    firewall_teardown_time: datetime | None = None
    firewall_teardown_observed: bool = True
    nat: NatSensorObservation | None = None

    def __post_init__(self) -> None:
        """Validate source-local interval and identifier invariants."""

        if not self.sensor_identity:
            raise ValueError("Network sensor observations require a sensor identity")
        if not self.connection_uid:
            raise ValueError("Network sensor observations require a connection UID")
        if (
            self.observed_close_time is not None
            and self.observed_close_time < self.observed_start_time
        ):
            raise ValueError("Observed network close cannot precede its start")
        if self.firewall_teardown_time is not None and self.firewall_teardown_time < (
            self.observed_start_time
        ):
            raise ValueError("Firewall teardown cannot precede the observed connection start")
        if self.firewall_teardown_reason and self.firewall_teardown_time is None:
            raise ValueError("Firewall teardown reasons require a planned teardown time")
        if (
            self.nat is not None
            and self.nat.nat_type == "dynamic_pat"
            and "cisco_asa" in self.visible_formats
            and self.nat.teardown_time != self.firewall_teardown_time
        ):
            raise ValueError("ASA dynamic NAT and connection teardown must share one lifetime")
        canonical_ids = [canonical for canonical, _observed in self.file_ids]
        if len(canonical_ids) != len(set(canonical_ids)):
            raise ValueError("Canonical file IDs must be unique within one sensor observation")
        observation_ids = [observation.canonical_id for observation in self.file_observations]
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("Canonical file observations must be unique within one sensor")
        if self.http_request_body_len is not None and self.http_request_body_len < 0:
            raise ValueError("Observed HTTP request bodies must be non-negative")
        if self.http_response_body_len is not None and self.http_response_body_len < 0:
            raise ValueError("Observed HTTP response bodies must be non-negative")

    @property
    def observed_duration(self) -> float | None:
        """Return the source-visible connection duration in seconds."""

        if self.observed_close_time is None:
            return None
        return (self.observed_close_time - self.observed_start_time).total_seconds()

    def file_id(self, canonical_id: str) -> str:
        """Return the sensor-local form of a canonical file identifier."""

        for candidate, observed in self.file_ids:
            if candidate == canonical_id:
                return observed
        return canonical_id

    def file_observation(self, canonical_id: str) -> FileSensorObservation | None:
        """Return source-local completeness for a canonical file identifier."""

        for observation in self.file_observations:
            if observation.canonical_id == canonical_id:
                return observation
        return None

    def connection_id(self, canonical_id: str) -> str:
        """Return the sensor-local form of a canonical connection identifier."""

        for candidate, observed in self.connection_ids:
            if candidate == canonical_id:
                return observed
        return canonical_id


@dataclass(frozen=True, slots=True)
class NetworkTransactionPlan:
    """Final canonical truth for one connection occurrence."""

    stable_id: str
    hostname: str
    outcome: NetworkTransactionOutcome
    phase_times: tuple[tuple[str, datetime], ...]
    started_at: datetime
    closed_at: datetime | None
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    service: str
    zeek_uid: str
    conn_id: str
    duration: float | None
    conn_state: str
    history: str
    traffic: NetworkTrafficLedger
    initiating_pid: int = -1
    responding_pid: int = -1
    local_orig: bool = True
    local_resp: bool = False
    ip_proto: int = 6
    link_local: bool = False
    application_layer_only: bool = False

    def __post_init__(self) -> None:
        """Validate interval and tuple invariants at the canonical boundary."""

        if not self.stable_id:
            raise ValueError("Network transaction stable_id cannot be empty")
        if any(not name for name, _timestamp in self.phase_times):
            raise ValueError("Network transaction phase names cannot be empty")
        if any(
            later_timestamp < earlier_timestamp
            for (_earlier_name, earlier_timestamp), (_later_name, later_timestamp) in zip(
                self.phase_times,
                self.phase_times[1:],
                strict=False,
            )
        ):
            raise ValueError("Network transaction phases must be chronologically ordered")
        if self.phase_times and self.phase_times[0][1] != self.started_at:
            raise ValueError("The first network transaction phase must anchor the start")
        if self.src_port < 0 or self.dst_port < 0:
            raise ValueError("Network transaction ports must be non-negative")
        if self.duration is not None and self.duration < 0:
            raise ValueError("Network transaction duration must be non-negative")
        if self.protocol in {"tcp", "udp"}:
            for direction in (self.traffic.orig, self.traffic.resp):
                if direction.packets and direction.ip_bytes > direction.packets * 1500:
                    raise ValueError(
                        "Canonical IP-byte accounting exceeds the modeled 1500-byte MTU"
                    )
        if self.closed_at is not None:
            if self.closed_at < self.started_at:
                raise ValueError("Network transaction close cannot precede its start")
            if self.duration is None:
                raise ValueError("Closed network transactions require a duration")
            expected_close = self.started_at + timedelta(seconds=self.duration)
            if abs((self.closed_at - expected_close).total_seconds()) > 0.000001:
                raise ValueError("Network transaction duration does not match its interval")
        elif self.duration is not None:
            raise ValueError("Network transaction duration requires a close timestamp")

    @property
    def orig_bytes(self) -> int:
        """Return canonical originator payload bytes."""

        return self.traffic.orig.payload_bytes

    @property
    def resp_bytes(self) -> int:
        """Return canonical responder payload bytes."""

        return self.traffic.resp.payload_bytes

    @property
    def orig_pkts(self) -> int:
        """Return canonical originator packet count."""

        return self.traffic.orig.packets

    @property
    def resp_pkts(self) -> int:
        """Return canonical responder packet count."""

        return self.traffic.resp.packets

    @property
    def orig_ip_bytes(self) -> int:
        """Return canonical originator IP-byte count."""

        return self.traffic.orig.ip_bytes

    @property
    def resp_ip_bytes(self) -> int:
        """Return canonical responder IP-byte count."""

        return self.traffic.resp.ip_bytes

    @property
    def missed_bytes(self) -> int:
        """Return canonical sensor-independent missed-byte budget."""

        return self.traffic.missed_bytes

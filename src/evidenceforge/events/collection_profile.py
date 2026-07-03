# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Blind-safe collection profile metadata for generated log packages."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.models.scenario import Scenario
from evidenceforge.output_targets import OutputTarget
from evidenceforge.utils.paths import safe_write_text
from evidenceforge.utils.time import resolve_time_window

COLLECTION_PROFILE_FILENAME = "COLLECTION_PROFILE.json"


class CollectionSourceFamily(BaseModel):
    """Collection semantics for a broad source family."""

    family: str
    formats: list[str] = Field(default_factory=list)
    primary_window: dict[str, str | None]
    tail_policy: str
    ordering: str
    notes: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class CollectionProfile(BaseModel):
    """Production-facing collection metadata safe for blind review packages."""

    schema_version: int = 1
    collection_window: dict[str, str | None]
    observation_profile: str
    output_target: str
    source_families: list[CollectionSourceFamily]

    model_config = ConfigDict(extra="forbid")


def build_collection_profile(
    scenario: Scenario,
    output_target: OutputTarget,
) -> CollectionProfile:
    """Build blind-safe source collection metadata for generated evidence."""
    collection_window = _collection_window(scenario)
    return CollectionProfile(
        collection_window=collection_window,
        observation_profile=scenario.observation_profile,
        output_target=output_target.value,
        source_families=[
            CollectionSourceFamily(
                family="network_sensors",
                formats=[
                    "zeek_conn",
                    "zeek_dns",
                    "zeek_http",
                    "zeek_ssl",
                    "zeek_smtp",
                    "zeek_files",
                    "zeek_x509",
                    "zeek_ocsp",
                    "zeek_dhcp",
                    "zeek_ntp",
                ],
                primary_window=collection_window,
                tail_policy=(
                    "Sensor records are clipped to the primary collection window; "
                    "boundary-spanning connections may close just outside the query horizon."
                ),
                ordering=(
                    "JSON exports are timestamp-normalized for consistent downstream analysis; "
                    "connection rows use the observed connection start timestamp."
                ),
                notes=[
                    "Protocol analyzer rows reference the connection UID visible to the sensor.",
                    "Companion file, TLS, certificate, DNS, SMTP, DHCP, and NTP rows stay tied "
                    "to the parent sensor interval when observed.",
                ],
            ),
            CollectionSourceFamily(
                family="perimeter_controls",
                formats=["cisco_asa", "snort_alert"],
                primary_window=collection_window,
                tail_policy=(
                    "Firewall and IDS exports use the primary window; long-lived sessions can "
                    "lack the opposite lifecycle record at the boundary."
                ),
                ordering="Text exports preserve source timestamp order within each device file.",
                notes=[
                    "NAT and alert records reflect the boundary device's view, not endpoint state.",
                ],
            ),
            CollectionSourceFamily(
                family="endpoint_telemetry",
                formats=[
                    "windows_event_security",
                    "windows_event_sysmon",
                    "ecar",
                    "syslog",
                    "bash_history",
                ],
                primary_window=collection_window,
                tail_policy=(
                    "Endpoint exports can include lifecycle closure rows after the primary "
                    "window when the initiating process, logon, service, or shell session was "
                    "visible or already active near the boundary."
                ),
                ordering=(
                    "Host files are sorted by source event timestamp after collector "
                    "normalization; durable source IDs remain monotonic within a host file."
                ),
                notes=[
                    "Missing pre-window initiators are expected for long-lived processes, "
                    "sessions, and services.",
                    "Endpoint flow attribution can be omitted when the collector cannot bind "
                    "a tuple to a stable process without breaking source-local causality.",
                ],
            ),
            CollectionSourceFamily(
                family="application_access",
                formats=["proxy_access", "web_access"],
                primary_window=collection_window,
                tail_policy=(
                    "Application access logs use the primary window and may include request "
                    "completion timestamps near the boundary."
                ),
                ordering="Access logs are written in source timestamp order within each host file.",
                notes=[
                    "Proxy rows may reflect authenticated users, machine context, service "
                    "traffic, or unauthenticated infrastructure requests.",
                ],
            ),
            CollectionSourceFamily(
                family="mail_artifacts",
                formats=["email_artifacts", "eml"],
                primary_window=collection_window,
                tail_policy=(
                    "Message artifact rows describe selected mailbox/export content; "
                    "metadata-only rows state why full RFC 5322 content is not present."
                ),
                ordering="The manifest is sorted by message date, message id, and sender.",
                notes=[
                    "The manifest excludes internal case identifiers, local filesystem paths, "
                    "classification labels, and transport route internals.",
                ],
            ),
        ],
    )


def write_collection_profile(
    output_dir: Path,
    scenario: Scenario,
    output_target: OutputTarget,
) -> None:
    """Write COLLECTION_PROFILE.json inside the generated data directory."""
    profile = build_collection_profile(scenario, output_target)
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_write_text(
        output_dir / COLLECTION_PROFILE_FILENAME,
        profile.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )


def _collection_window(scenario: Scenario) -> dict[str, str | None]:
    try:
        start, end = resolve_time_window(scenario.time_window)
    except ValueError:
        start = scenario.time_window.start
        end = None
    return {
        "start": _format_dt(start),
        "end": _format_dt(end) if end else None,
    }


def _format_dt(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat().replace("+00:00", "Z")

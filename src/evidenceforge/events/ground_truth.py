# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical machine-readable ground truth document for generated datasets."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.paths import safe_write_text
from evidenceforge.utils.time import resolve_time_window

logger = logging.getLogger(__name__)

GROUND_TRUTH_JSON_FILENAME = "GROUND_TRUTH.json"
GROUND_TRUTH_SCHEMA_VERSION = 1
MAX_GROUND_TRUTH_BYTES = 8_388_608

GroundTruthSection = Literal["storyline", "red_herring"]


class GroundTruthAttributesBase(BaseModel):
    """Known ground-truth attribute fields across tracked event kinds."""

    action: str | None = None
    artifact_id: str | None = None
    artifact_path: str | None = None
    attempt_count: int | None = None
    base_domain: str | None = None
    bytes_exfiltrated: int | None = None
    command_line: str | None = None
    count: int | None = None
    domain_sample: list[str] | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    encoding: str | None = None
    expected_sources: list[str] | None = None
    family: str | None = None
    group_name: str | None = None
    interval: str | int | float | None = None
    logon_id: str | None = None
    logon_type: int | None = None
    mail_action: str | None = None
    mac_address: str | None = None
    member_name: str | None = None
    message_id: str | None = None
    network_target: str | None = None
    network_target_ip: str | None = None
    network_target_port: int | None = None
    network_url: str | None = None
    nxdomain_count: int | None = None
    output_file: str | None = None
    outcome: str | None = None
    pattern: str | None = None
    pid: int | None = None
    ports: list[int] | None = None
    preset: str | None = None
    process_name: str | None = None
    protocol: str | None = None
    qtype: str | None = None
    query: str | None = None
    rcode: str | None = None
    recipients: list[str] | None = None
    rendered_value: str | None = None
    rendered_sha256: str | None = None
    request_count: int | None = None
    scheme: str | None = None
    service_file_name: str | None = None
    service_name: str | None = None
    sender: str | None = None
    smtp_uids: list[str] | None = None
    source_ip: str | None = None
    staged_archive: str | None = None
    success_account: str | None = None
    success_at_attempt: int | None = None
    subject: str | None = None
    surface: str | None = None
    target_accounts: list[str] | None = None
    target_count: int | None = None
    target_format: str | None = None
    target_process: str | None = None
    target_server: str | None = None
    target_system: str | None = None
    target_username: str | None = None
    task_content: str | None = None
    task_name: str | None = None
    termination: str | None = None
    tld: str | None = None
    total_connections: int | None = None
    total_queries: int | None = None
    uid: str | None = None
    value: str | None = None
    value_sha256: str | None = None
    verdict: str | None = None
    route: list[dict[str, str]] | None = None

    model_config = ConfigDict(extra="forbid")


class ProcessAttributes(GroundTruthAttributesBase):
    """Process event attributes."""


class LogonAttributes(GroundTruthAttributesBase):
    """Logon event attributes."""


class FailedLogonAttributes(GroundTruthAttributesBase):
    """Failed logon event attributes."""


class LogoffAttributes(GroundTruthAttributesBase):
    """Logoff event attributes."""


class ConnectionAttributes(GroundTruthAttributesBase):
    """Connection event attributes."""


class SshSessionAttributes(GroundTruthAttributesBase):
    """SSH session event attributes."""


class RdpSessionAttributes(GroundTruthAttributesBase):
    """RDP session event attributes."""


class AccountCreatedAttributes(GroundTruthAttributesBase):
    """Account-created event attributes."""


class AccountDeletedAttributes(GroundTruthAttributesBase):
    """Account-deleted event attributes."""


class GroupMemberAddedAttributes(GroundTruthAttributesBase):
    """Group-member-added event attributes."""


class ServiceInstalledAttributes(GroundTruthAttributesBase):
    """Service-installed event attributes."""


class ScheduledTaskCreatedAttributes(GroundTruthAttributesBase):
    """Scheduled-task-created event attributes."""


class LogClearedAttributes(GroundTruthAttributesBase):
    """Log-cleared event attributes."""


class CreateRemoteThreadAttributes(GroundTruthAttributesBase):
    """Create-remote-thread event attributes."""


class ProcessAccessAttributes(GroundTruthAttributesBase):
    """Process-access event attributes."""


class DhcpLeaseAttributes(GroundTruthAttributesBase):
    """DHCP lease event attributes."""


class PortScanAttributes(GroundTruthAttributesBase):
    """Port-scan event attributes."""


class BeaconAttributes(GroundTruthAttributesBase):
    """Beacon event attributes."""


class DnsQueryAttributes(GroundTruthAttributesBase):
    """DNS query event attributes."""


class WebScanAttributes(GroundTruthAttributesBase):
    """Web-scan event attributes."""


class CredentialSprayAttributes(GroundTruthAttributesBase):
    """Credential-spray event attributes."""


class DgaQueriesAttributes(GroundTruthAttributesBase):
    """DGA-queries event attributes."""


class DnsTunnelAttributes(GroundTruthAttributesBase):
    """DNS-tunnel event attributes."""


class ExplicitCredentialsAttributes(GroundTruthAttributesBase):
    """Explicit-credentials event attributes."""


class WorkstationLockAttributes(GroundTruthAttributesBase):
    """Workstation-lock event attributes."""


class WorkstationUnlockAttributes(GroundTruthAttributesBase):
    """Workstation-unlock event attributes."""


class SpillageAttributes(GroundTruthAttributesBase):
    """Spillage event attributes."""

    surface: str
    expected_sources: list[str] = Field(default_factory=list)


class IdsAlertAttributes(BaseModel):
    """The on-wire Snort/Suricata signature an adversarial payload should trip.

    Correlation evidence (distinct from ``expected_sources``): the Snort/IDS alert
    line references this SID, not the payload text, so it documents the detection a
    network sensor should fire when the payload rides a cleartext http request.
    """

    sid: int
    rev: int = 1
    message: str

    model_config = ConfigDict(extra="forbid")


class AdversarialPayloadAttributes(GroundTruthAttributesBase):
    """Adversarial-payload event attributes (the counterpart to spillage)."""

    surface: str
    expected_sources: list[str] = Field(default_factory=list)
    # The operator-registered live-callback (OOB) host the payload points at, when a
    # generation run opted into live callbacks (`eforge generate --oob-host`). None for
    # the default inert-canary runs.
    callback_host: str | None = None
    # The family's weakness class and the pass criterion a hardened pipeline must meet
    # (CWE/CVE class + what to verify) — propagated so an analyst can SCORE the payload
    # from ground truth alone. None for a literal `value:` payload (no family).
    weakness_class: str | None = None
    expected_defender_signal: str | None = None
    # The on-wire IDS signature a network sensor should fire on for this payload, when
    # it rides a cleartext http request and the family maps to a signature. None for
    # https (opaque), syslog/process surfaces, or families with no network signature.
    ids_alert: IdsAlertAttributes | None = None


class RawAttributes(GroundTruthAttributesBase):
    """Raw event attributes."""

    target_format: str


class GroundTruthEventBase(BaseModel):
    """Shared event envelope for canonical ground-truth records."""

    record_id: str
    kind: str
    storyline_id: str | None = None
    time: datetime
    actor: str
    system: str
    activity: str
    ground_truth_section: GroundTruthSection
    emitted: bool
    skipped_reason: str | None = None
    explanation: str | None = None

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_emission_fields(self) -> GroundTruthEventBase:
        """Require skipped_reason for non-emitted events and forbid it otherwise."""
        if self.emitted and self.skipped_reason is not None:
            raise ValueError("skipped_reason is only valid when emitted=false")
        if not self.emitted and not self.skipped_reason:
            raise ValueError("skipped_reason is required when emitted=false")
        if self.explanation is not None and self.ground_truth_section != "red_herring":
            raise ValueError("explanation is only valid for red_herring events")
        return self


class ProcessGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["process"]
    attributes: ProcessAttributes = Field(default_factory=ProcessAttributes)


class LogonGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["logon"]
    attributes: LogonAttributes = Field(default_factory=LogonAttributes)


class FailedLogonGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["failed_logon"]
    attributes: FailedLogonAttributes = Field(default_factory=FailedLogonAttributes)


class LogoffGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["logoff"]
    attributes: LogoffAttributes = Field(default_factory=LogoffAttributes)


class ConnectionGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["connection"]
    attributes: ConnectionAttributes = Field(default_factory=ConnectionAttributes)


class SshSessionGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["ssh_session"]
    attributes: SshSessionAttributes = Field(default_factory=SshSessionAttributes)


class RdpSessionGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["rdp_session"]
    attributes: RdpSessionAttributes = Field(default_factory=RdpSessionAttributes)


class AccountCreatedGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["account_created"]
    attributes: AccountCreatedAttributes = Field(default_factory=AccountCreatedAttributes)


class AccountDeletedGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["account_deleted"]
    attributes: AccountDeletedAttributes = Field(default_factory=AccountDeletedAttributes)


class GroupMemberAddedGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["group_member_added"]
    attributes: GroupMemberAddedAttributes = Field(default_factory=GroupMemberAddedAttributes)


class ServiceInstalledGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["service_installed"]
    attributes: ServiceInstalledAttributes = Field(default_factory=ServiceInstalledAttributes)


class ScheduledTaskCreatedGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["scheduled_task_created"]
    attributes: ScheduledTaskCreatedAttributes = Field(
        default_factory=ScheduledTaskCreatedAttributes
    )


class LogClearedGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["log_cleared"]
    attributes: LogClearedAttributes = Field(default_factory=LogClearedAttributes)


class CreateRemoteThreadGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["create_remote_thread"]
    attributes: CreateRemoteThreadAttributes = Field(default_factory=CreateRemoteThreadAttributes)


class ProcessAccessGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["process_access"]
    attributes: ProcessAccessAttributes = Field(default_factory=ProcessAccessAttributes)


class DhcpLeaseGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["dhcp_lease"]
    attributes: DhcpLeaseAttributes = Field(default_factory=DhcpLeaseAttributes)


class PortScanGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["port_scan"]
    attributes: PortScanAttributes = Field(default_factory=PortScanAttributes)


class BeaconGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["beacon"]
    attributes: BeaconAttributes = Field(default_factory=BeaconAttributes)


class DnsQueryGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["dns_query"]
    attributes: DnsQueryAttributes = Field(default_factory=DnsQueryAttributes)


class EmailMessageAttributes(GroundTruthAttributesBase):
    """Email message event attributes."""


class EmailMessageGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["email_message"]
    attributes: EmailMessageAttributes = Field(default_factory=EmailMessageAttributes)


class WebScanGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["web_scan"]
    attributes: WebScanAttributes = Field(default_factory=WebScanAttributes)


class CredentialSprayGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["credential_spray"]
    attributes: CredentialSprayAttributes = Field(default_factory=CredentialSprayAttributes)


class DgaQueriesGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["dga_queries"]
    attributes: DgaQueriesAttributes = Field(default_factory=DgaQueriesAttributes)


class DnsTunnelGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["dns_tunnel"]
    attributes: DnsTunnelAttributes = Field(default_factory=DnsTunnelAttributes)


class ExplicitCredentialsGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["explicit_credentials"]
    attributes: ExplicitCredentialsAttributes = Field(default_factory=ExplicitCredentialsAttributes)


class WorkstationLockGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["workstation_lock"]
    attributes: WorkstationLockAttributes = Field(default_factory=WorkstationLockAttributes)


class WorkstationUnlockGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["workstation_unlock"]
    attributes: WorkstationUnlockAttributes = Field(default_factory=WorkstationUnlockAttributes)


class SpillageGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["spillage"]
    attributes: SpillageAttributes

    @model_validator(mode="after")
    def validate_spillage_payload(self) -> SpillageGroundTruthEvent:
        """Keep spillage emitted/skipped semantics explicit and consistent."""
        attrs = self.attributes
        value_fields = (
            attrs.value,
            attrs.value_sha256,
            attrs.rendered_value,
        )
        if self.emitted:
            if not all(value_fields) or attrs.expected_sources is None:
                raise ValueError(
                    "emitted spillage events require value/value_sha256/rendered_value and expected_sources"
                )
        else:
            if any(value_fields):
                raise ValueError("skipped spillage events must not carry emitted value fields")
        return self


class AdversarialPayloadGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["adversarial_payload"]
    attributes: AdversarialPayloadAttributes

    @model_validator(mode="after")
    def validate_adversarial_payload(self) -> AdversarialPayloadGroundTruthEvent:
        """Keep adversarial-payload emitted/skipped semantics explicit and consistent."""
        attrs = self.attributes
        value_fields = (attrs.value, attrs.value_sha256, attrs.rendered_value)
        if self.emitted:
            if not all(value_fields) or attrs.expected_sources is None:
                raise ValueError(
                    "emitted adversarial_payload events require "
                    "value/value_sha256/rendered_value and expected_sources"
                )
        else:
            if any(value_fields):
                raise ValueError(
                    "skipped adversarial_payload events must not carry emitted value fields"
                )
        return self


class RawGroundTruthEvent(GroundTruthEventBase):
    kind: Literal["raw"]
    attributes: RawAttributes


GroundTruthEvent = Annotated[
    ProcessGroundTruthEvent
    | LogonGroundTruthEvent
    | FailedLogonGroundTruthEvent
    | LogoffGroundTruthEvent
    | ConnectionGroundTruthEvent
    | SshSessionGroundTruthEvent
    | RdpSessionGroundTruthEvent
    | AccountCreatedGroundTruthEvent
    | AccountDeletedGroundTruthEvent
    | GroupMemberAddedGroundTruthEvent
    | ServiceInstalledGroundTruthEvent
    | ScheduledTaskCreatedGroundTruthEvent
    | LogClearedGroundTruthEvent
    | CreateRemoteThreadGroundTruthEvent
    | ProcessAccessGroundTruthEvent
    | DhcpLeaseGroundTruthEvent
    | PortScanGroundTruthEvent
    | BeaconGroundTruthEvent
    | DnsQueryGroundTruthEvent
    | EmailMessageGroundTruthEvent
    | WebScanGroundTruthEvent
    | CredentialSprayGroundTruthEvent
    | DgaQueriesGroundTruthEvent
    | DnsTunnelGroundTruthEvent
    | ExplicitCredentialsGroundTruthEvent
    | WorkstationLockGroundTruthEvent
    | WorkstationUnlockGroundTruthEvent
    | SpillageGroundTruthEvent
    | AdversarialPayloadGroundTruthEvent
    | RawGroundTruthEvent,
    Field(discriminator="kind"),
]


class GroundTruthStep(BaseModel):
    """Ordered storyline/red-herring step metadata for Markdown reconstruction."""

    storyline_id: str
    index: int = Field(ge=0)
    actor: str
    system: str
    activity: str
    ground_truth_section: GroundTruthSection
    event_types: list[str] = Field(default_factory=list)
    explanation: str | None = None

    model_config = ConfigDict(extra="forbid")


class GroundTruthDocument(BaseModel):
    """Canonical machine-readable ground-truth document."""

    schema_version: int = GROUND_TRUTH_SCHEMA_VERSION
    scenario_name: str
    scenario_description: str
    generated_at: datetime
    observation_profile: str
    collection_window: dict[str, str | None]
    source_evidence_status: dict[str, dict[str, dict[str, int]]] = Field(default_factory=dict)
    storyline_steps: list[GroundTruthStep] = Field(default_factory=list)
    red_herring_steps: list[GroundTruthStep] = Field(default_factory=list)
    events: list[GroundTruthEvent] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


def write_ground_truth_document(output_path: Path, document: GroundTruthDocument) -> None:
    """Write the canonical ground-truth document."""
    safe_write_text(
        output_path,
        document.model_dump_json(indent=2, exclude_none=True) + "\n",
        encoding="utf-8",
    )


def find_ground_truth_document(output_dir: Path) -> Path | None:
    """Find a trusted ground-truth JSON document for an eval output directory."""
    output_root = output_dir.resolve()
    allowed_parents = {output_root, output_root.parent}
    candidates = [
        output_dir / GROUND_TRUTH_JSON_FILENAME,
        output_dir.parent / GROUND_TRUTH_JSON_FILENAME,
    ]
    for candidate in candidates:
        if candidate.is_symlink():
            logger.warning("Ignoring symlinked ground-truth document %s", candidate)
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.parent not in allowed_parents:
            logger.warning("Ignoring out-of-root ground-truth document %s", candidate)
            continue
        if not resolved.is_file():
            continue
        if resolved.stat().st_size > MAX_GROUND_TRUTH_BYTES:
            logger.warning("Ignoring oversized ground-truth document %s", candidate)
            continue
        return resolved
    return None


def load_ground_truth_document(
    output_dir: Path,
    scenario: Scenario | None = None,
) -> GroundTruthDocument | None:
    """Load a canonical ground-truth document for eval, returning None if invalid."""
    path = find_ground_truth_document(output_dir)
    if path is None:
        return None
    try:
        document = GroundTruthDocument.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        logger.warning("Ignoring invalid ground-truth document %s: %s", path, exc)
        return None
    if scenario is not None and not ground_truth_document_matches_scenario(document, scenario):
        logger.warning("Ignoring ground-truth document %s because it does not match scenario", path)
        return None
    return document


def ground_truth_document_matches_scenario(
    document: GroundTruthDocument,
    scenario: Scenario,
) -> bool:
    """Return whether a ground-truth document is bound to the supplied scenario."""
    return (
        document.scenario_name == scenario.name
        and document.scenario_description == scenario.description
        and document.observation_profile == scenario.observation_profile
        and document.collection_window == _collection_window(scenario)
    )


def _collection_window(scenario: Scenario) -> dict[str, str | None]:
    """Return the scenario collection window in canonical serialized form."""
    start, end = resolve_time_window(scenario.time_window)
    start = start.replace(tzinfo=UTC) if start.tzinfo is None else start.astimezone(UTC)
    end = (
        end.replace(tzinfo=UTC)
        if end and end.tzinfo is None
        else (end.astimezone(UTC) if end else None)
    )
    return {
        "start": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end": end.strftime("%Y-%m-%dT%H:%M:%SZ") if end else None,
    }

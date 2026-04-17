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

"""Scenario models for EvidenceForge.

This module defines Pydantic models for scenario files. These models describe
the computing environment, users, systems, personas, and storylines for log generation.

Note: Phase 1 implementation is simplified. Many fields are stored as-is without
LLM expansion or complex parsing. Phase 2/3 will add:
- LLM expansion of personas into detailed activity plans
- Work hours parsing into time distributions
- Semantic validation and cross-reference resolution
"""

import ipaddress
import re
from datetime import datetime
from typing import Annotated, Any, Literal

import pytz
from pydantic import (
    BaseModel,
    ConfigDict,
    Discriminator,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

_HOSTNAME_RE = re.compile(
    r"^(?!-)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?)*$"
)


def _validate_hostname(v: str, field_name: str = "hostname") -> str:
    """Validate a bare hostname/FQDN — reject schemes, ports, paths, whitespace."""
    if not v:
        return v
    if "://" in v or "/" in v or ":" in v or " " in v or "\t" in v:
        raise ValueError(
            f"{field_name} must be a bare hostname (no scheme, port, path, or whitespace): {v!r}"
        )
    if not _HOSTNAME_RE.match(v):
        raise ValueError(f"{field_name} is not a valid hostname: {v!r}")
    return v


class TimeWindow(BaseModel):
    """Time window for log generation.

    Specifies when log generation should start and end. Either 'end' or 'duration'
    must be specified (but not both).

    Attributes:
        start: Start time in ISO 8601 UTC format (e.g., "2024-01-15T10:00:00Z")
        end: End time in ISO 8601 UTC format (mutually exclusive with duration)
        duration: Duration string like "10h", "3d", "2h30m" (mutually exclusive with end)
        warmup: Warm-up duration before start for state pre-population (default "8h").
            Events generated during warm-up populate DNS cache, process trees, sessions,
            and other internal state but are NOT written to output files. Minimum 1 hour.
    """

    start: datetime = Field(..., description="Start time (ISO 8601 UTC)")
    end: datetime | None = Field(None, description="End time (ISO 8601 UTC)")
    duration: str | None = Field(None, description="Duration string (e.g., '10h', '3d')")
    warmup: str | None = Field(
        default="8h",
        description="Warm-up duration before start for state pre-population (e.g., '8h', '2h'). "
        "Minimum 1 hour.",
    )

    @field_validator("duration")
    @classmethod
    def validate_duration_format(cls, v: str | None) -> str | None:
        """Validate duration format matches pattern like '10h', '3d', '2h30m', '5m30s'.

        Phase 1 only validates format, not semantics. Parsing into timedelta
        happens in utils/time.py.
        """
        if v is None:
            return None
        # Allow multiple digit-unit pairs like "2h30m", "5m30s", "500ms"
        if not re.match(r"^(\d+(ms|[hdms]))+$", v):
            raise ValueError(
                "Duration must match pattern like '10h', '3d', '2h30m', '5m30s', '500ms' "
                "(digits followed by d/h/m/s/ms units)"
            )
        return v

    @field_validator("warmup")
    @classmethod
    def validate_warmup_format(cls, v: str | None) -> str | None:
        """Validate warmup format and enforce minimum 1 hour."""
        if v is None:
            return None
        if not re.match(r"^(\d+(ms|[hdms]))+$", v):
            raise ValueError(
                "warmup must match pattern like '8h', '2h', '1h30m' "
                "(digits followed by d/h/m/s/ms units)"
            )
        # Enforce minimum 1 hour — warm-up is essential for realistic output
        from evidenceforge.utils.time import parse_duration

        duration = parse_duration(v)
        if duration.total_seconds() < 3600:
            raise ValueError(
                f"warmup must be at least 1 hour (got '{v}'). "
                "Warm-up pre-populates DNS cache, process trees, and sessions "
                "needed for realistic output."
            )
        return v

    @model_validator(mode="after")
    def check_end_or_duration(self):
        """Ensure exactly one of end or duration is specified."""
        if self.end is None and self.duration is None:
            raise ValueError("Either 'end' or 'duration' must be specified")
        if self.end is not None and self.duration is not None:
            raise ValueError("Cannot specify both 'end' and 'duration'")
        return self


class User(BaseModel):
    """User definition (simplified for Phase 1).

    Represents a user in the simulated environment who may generate log activity.

    Attributes:
        username: Username (alphanumeric, dot, dollar sign, dash, underscore)
        full_name: User's full name
        email: Email address (basic format validation)
        groups: List of group names this user belongs to
        enabled: If False, user generates no activity
        persona: Reference to a persona name (if None, no activity generated)
        primary_system: Primary system hostname for this user (optional)
    """

    username: str = Field(..., pattern=r"^[a-zA-Z0-9._$-]+$")
    full_name: str
    email: str
    groups: list[str] = Field(default_factory=list)
    enabled: bool = Field(default=True)
    persona: str | None = Field(None, description="Reference to persona name")
    primary_system: str | None = Field(None, description="Primary system hostname")
    browsing_intensity: str | None = Field(
        None,
        pattern="^(light|normal|heavy)$",
        description="Per-user browsing intensity override (takes precedence over persona)",
    )

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        """Basic email validation (format check only)."""
        if not re.match(r"^[a-zA-Z0-9._%+$-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", v):
            raise ValueError(f"Invalid email format: {v}")
        return v


class System(BaseModel):
    """System definition (simplified for Phase 1).

    Represents a computer system (workstation, server, domain controller)
    in the simulated environment.

    Attributes:
        hostname: Hostname (RFC 1123 compliant)
        ip: IPv4 or IPv6 address
        os: Operating system name/version (e.g., "Windows 10", "Linux Ubuntu 20.04")
        type: System type (workstation|server|domain_controller)
        assigned_user: Username of assigned user (for workstations)
        services: List of running services (e.g., ["IIS", "SSH", "SQL Server"])
    """

    hostname: str = Field(..., pattern="^[a-zA-Z0-9][a-zA-Z0-9.-]*$")
    ip: str
    os: str
    type: str = Field(..., pattern="^(workstation|server|domain_controller)$")
    assigned_user: str | None = None
    services: list[str] = Field(default_factory=list)
    roles: list[str] = Field(
        default_factory=list,
        description="System roles: forward_proxy, web_server, dns_server, mail_server, etc.",
    )
    public_hostnames: list[str] = Field(
        default_factory=list,
        description="Public DNS names for internet-facing services (e.g., 'ehr-portal.example.com'). "
        "Used for TLS SNI / HTTP Host in external inbound traffic.",
    )

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(v)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {v}") from e
        return v

    @field_validator("public_hostnames")
    @classmethod
    def validate_public_hostnames(cls, v: list[str]) -> list[str]:
        """Validate each public hostname is a bare FQDN."""
        return [_validate_hostname(h, "public_hostnames") for h in v]


class Group(BaseModel):
    """Group definition (simplified for Phase 1).

    Represents a user group in the simulated environment.

    Attributes:
        name: Group name
        description: Optional group description
        members: List of usernames in this group
        permissions: Optional list of permissions (Phase 1: stored as strings)
    """

    name: str
    description: str | None = None
    members: list[str] = Field(default_factory=list)
    permissions: list[str] | None = None


class Persona(BaseModel):
    """Persona definition with optional LLM expansion fields.

    Phase 1: Basic string descriptions (typical_activities, work_hours)
    Phase 2.4: Add optional expanded_activities for future LLM population
    Phase 2.6: Persona-based activity generation uses expanded_activities
    Phase 3.1: LLM expands descriptions into expanded_activities

    Attributes:
        name: Persona name (e.g., "developer", "accountant")
        description: Natural language behavior description
        typical_activities: List of typical activities (Phase 1: stored as strings)
        work_hours: Work hours description (e.g., "9am-5pm", "8:30am-5:30pm (lunch 12pm-1pm)")
        application_usage: List of applications this persona uses
        risk_profile: Activity risk level (low|medium|high)
        expanded_activities: Optional detailed activity sequences (Phase 3.1 LLM-populated)
        work_hours_parsed: Optional parsed work hours distribution (auto-populated)
        activity_intensity: Optional per-activity-type intensity overrides (events/hour)
    """

    # Phase 1 fields (required/default)
    name: str
    description: str
    typical_activities: list[str] = Field(default_factory=list)
    work_hours: str = Field(default="9am-5pm")
    application_usage: list[str] = Field(default_factory=list)
    risk_profile: str = Field(default="medium", pattern="^(low|medium|high)$")
    browsing_intensity: str = Field(
        default="normal",
        pattern="^(light|normal|heavy)$",
        description="Browsing session depth: light (1 page), normal (1-2 pages), heavy (2-4 pages)",
    )

    # Phase 2.4 optional fields (backward compatible - prepare for future LLM expansion)
    expanded_activities: list[dict[str, Any]] | None = Field(
        None, description="Detailed activity sequences (populated by LLM in Phase 3.1)"
    )
    work_hours_parsed: dict[str, Any] | None = Field(
        None, description="Parsed work hours distribution (auto-populated from work_hours)"
    )
    activity_intensity: dict[str, int] | None = Field(
        None, description="Per-activity-type intensity overrides (events/hour)"
    )

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def parse_work_hours_on_load(self) -> "Persona":
        """Auto-populate work_hours_parsed if not provided.

        Phase 2.4: Parse work_hours string into structured time distribution.
        """
        if self.work_hours_parsed is None and self.work_hours:
            try:
                # Import here to avoid circular dependency
                from evidenceforge.utils.time import parse_work_hours

                self.work_hours_parsed = parse_work_hours(self.work_hours)
            except Exception:
                # If parsing fails, leave work_hours_parsed as None
                # This maintains backward compatibility with invalid work_hours strings
                pass
        return self


class BaselineActivity(BaseModel):
    """Baseline activity configuration (simplified for Phase 1).

    Defines the baseline ("normal") activity level and variation for the environment.

    Attributes:
        description: Natural language description of baseline activity
        intensity: Activity intensity (low|medium|high)
                  Phase 1 mapping: low=5, medium=15, high=40 events/user/hour
        variation: Timing variation (low|medium|high)
                  Phase 1 mapping: low=±10%, medium=±25%, high=±50% stddev
        suspicious_noise: Level of suspicious-but-benign ambient noise
                  low=~1/hr, medium=~2/hr, high=~3/hr, ludicrous=~5/hr (default: high)
    """

    description: str
    intensity: str = Field(..., pattern="^(low|medium|high)$")
    variation: str = Field(..., pattern="^(low|medium|high)$")
    suspicious_noise: str = Field(
        default="high",
        pattern="^(low|medium|high|ludicrous)$",
        description="Level of suspicious-but-benign ambient noise (default: high)",
    )

    model_config = ConfigDict(extra="forbid")


# --- Phase 8.4: Per-event-type Pydantic models for typed storyline declarations ---


class _EventSpecBase(BaseModel):
    """Base for all event spec models. Common optional metadata fields."""

    technique: str | None = None  # MITRE ATT&CK technique ID (for GROUND_TRUTH.md)
    description: str | None = None  # Human-readable description (for GROUND_TRUTH.md)
    model_config = ConfigDict(extra="forbid")


class ProcessEventSpec(_EventSpecBase):
    """Process execution event (generates 4688, Sysmon 1, eCAR PROCESS/CREATE)."""

    type: Literal["process"] = "process"
    process_name: str
    command_line: str | None = None  # defaults to process_name at generation time
    supplementary: Literal["auto", "none"] = "auto"


class LogonEventSpec(_EventSpecBase):
    """Authentication event (generates 4624, 4672, eCAR USER_SESSION/LOGIN)."""

    type: Literal["logon"] = "logon"
    logon_type: int = 3
    source_ip: str | None = None


class FailedLogonEventSpec(_EventSpecBase):
    """Failed authentication event (generates 4625, eCAR USER_SESSION/LOGIN failure).

    If target_username is set, the failed logon targets that user (e.g., help desk
    testing a locked-out account). Otherwise, the actor is used as the target.
    """

    type: Literal["failed_logon"] = "failed_logon"
    source_ip: str | None = None
    logon_type: int = 3
    target_username: str | None = None


class LogoffEventSpec(_EventSpecBase):
    """Logoff event (generates 4634, eCAR USER_SESSION/LOGOUT)."""

    type: Literal["logoff"] = "logoff"


class ConnectionEventSpec(_EventSpecBase):
    """Network connection event (generates Zeek conn, eCAR FLOW, optionally web_access/zeek_http)."""

    type: Literal["connection"] = "connection"
    dst_ip: str
    dst_port: int = 443
    hostname: str | None = None  # Domain name for DNS/SSL SNI (omit for raw-IP C2)
    service: str | None = None  # ssl, http, etc.
    source_ip: str | None = None
    # HTTP fields (when service=http, produces correlated web_access + zeek_http)
    method: str | None = None  # GET, POST, etc.
    uri: str | None = None  # Request URI path
    status_code: int | None = None  # HTTP response status
    user_agent: str | None = None  # Client User-Agent string
    response_body_len: int | None = None  # Override auto-sized response bytes
    # Override auto-sized byte counts and connection outcome
    orig_bytes: int | None = None  # Originator payload bytes (large for exfil)
    resp_bytes: int | None = None  # Responder payload bytes (large for downloads)
    conn_state: str | None = None  # Connection outcome (default: SF for storyline)

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str | None) -> str | None:
        """Validate hostname is a bare FQDN (no scheme/port/path)."""
        if v is not None:
            _validate_hostname(v, "connection.hostname")
        return v


class SshSessionEventSpec(_EventSpecBase):
    """SSH session event (generates Zeek conn + syslog sshd + eCAR)."""

    type: Literal["ssh_session"] = "ssh_session"
    source_ip: str | None = None


class RdpSessionEventSpec(_EventSpecBase):
    """RDP session event (generates Zeek conn + 4624 type 10 + eCAR on target)."""

    type: Literal["rdp_session"] = "rdp_session"
    source_ip: str | None = None


class AccountCreatedEventSpec(_EventSpecBase):
    """Account creation event (generates 4720 on DC)."""

    type: Literal["account_created"] = "account_created"
    target_username: str
    target_sid: str | None = None  # auto-generated from domain SID if not provided


class AccountDeletedEventSpec(_EventSpecBase):
    """Account deletion event (generates 4726 on DC)."""

    type: Literal["account_deleted"] = "account_deleted"
    target_username: str
    target_sid: str | None = None


class GroupMemberAddedEventSpec(_EventSpecBase):
    """Group membership change event (generates 4728/4732/4756 on DC)."""

    type: Literal["group_member_added"] = "group_member_added"
    group_name: str
    member_name: str
    scope: Literal["global", "local", "universal"] = "global"


class ServiceInstalledEventSpec(_EventSpecBase):
    """Service installation event (generates 4697)."""

    type: Literal["service_installed"] = "service_installed"
    service_name: str
    service_file_name: str
    service_account: str = "LocalSystem"


class ScheduledTaskCreatedEventSpec(_EventSpecBase):
    """Scheduled task creation event (generates 4698)."""

    type: Literal["scheduled_task_created"] = "scheduled_task_created"
    task_name: str
    task_content: str | None = None


class LogClearedEventSpec(_EventSpecBase):
    """Security log cleared event (generates 1102)."""

    type: Literal["log_cleared"] = "log_cleared"


class CreateRemoteThreadEventSpec(_EventSpecBase):
    """Remote thread injection event (generates Sysmon Event 8)."""

    type: Literal["create_remote_thread"] = "create_remote_thread"
    target_process: str


class ProcessAccessEventSpec(_EventSpecBase):
    """Process access event (generates Sysmon Event 10)."""

    type: Literal["process_access"] = "process_access"
    target_process: str = "lsass.exe"
    access_mask: str = "0x1010"


class DhcpLeaseEventSpec(_EventSpecBase):
    """DHCP lease event for rogue/new devices appearing on the network."""

    type: Literal["dhcp_lease"] = "dhcp_lease"
    mac_address: str | None = None
    requested_ip: str | None = None
    model_config = ConfigDict(extra="forbid")


class PortScanEventSpec(_EventSpecBase):
    """Port scan producing firewall deny records (ASA 106023).

    Generates many denied connection attempts from the storyline system to
    target IPs/segments. Covers external recon scans, host sweeps, lateral
    scans through internal firewalls, and worm-like propagation.
    """

    type: Literal["port_scan"] = "port_scan"
    source_ip: str = ""  # Override scan source IP (default: uses storyline system IP)
    target_ips: list[str] = Field(default_factory=list)
    target_segment: str | None = None
    target_count: int = Field(default=50, ge=1, le=5000)
    ports: list[int] = Field(default_factory=lambda: [22, 80, 443, 445, 3389])
    protocol: str = Field(default="tcp", pattern="^(tcp|udp|icmp)$")
    scan_rate: float = Field(default=100.0, gt=0.0)


_DURATION_RE = re.compile(r"^(\d+(ms|[hdms]))+$")


def _validate_duration_string(v: str, field_name: str) -> str:
    """Validate a duration string format and enforce > 0 seconds."""
    if not _DURATION_RE.match(v):
        raise ValueError(
            f"{field_name} must match pattern like '30m', '6h', or '5m30s' "
            "(digits followed by d/h/m/s/ms units)"
        )
    from evidenceforge.utils.time import parse_duration

    seconds = parse_duration(v).total_seconds()
    if seconds <= 0:
        raise ValueError(f"{field_name} must be greater than 0 seconds (got '{v}')")
    return v


_VALID_QTYPES = {"A", "AAAA", "TXT", "CNAME", "MX", "NULL", "SRV", "PTR"}
_VALID_RCODES = {"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"}


class _PeriodicEventBase(_EventSpecBase):
    """Shared timing fields for all periodic/bulk event types.

    Provides interval-based or rate-based timing, with exactly one
    termination condition (end_time, duration, or count).
    """

    start_time: str | None = None  # ISO 8601 or relative offset; defaults to parent event time
    interval: str | None = None  # Duration between events (e.g., "5m", "30s")
    rate: float | None = None  # Events per second; mutually exclusive with interval
    end_time: str | None = None  # ISO 8601 or relative offset
    duration: str | None = None  # Total campaign length (e.g., "7d", "2h")
    count: int | None = Field(default=None, ge=1)  # Exact number of events to emit
    jitter: float = Field(default=0.2, ge=0.0, le=1.0)

    @field_validator("interval", "duration")
    @classmethod
    def validate_duration_fields(cls, v: str | None, info: ValidationInfo) -> str | None:
        """Validate interval/duration format and enforce > 0."""
        if v is not None:
            _validate_duration_string(v, info.field_name)
        return v

    @field_validator("rate")
    @classmethod
    def validate_positive_rate(cls, v: float | None) -> float | None:
        """Rate must be positive."""
        if v is not None and v <= 0:
            raise ValueError("rate must be greater than 0")
        return v

    @model_validator(mode="after")
    def check_termination(self) -> "_PeriodicEventBase":
        """Exactly one of end_time, duration, or count must be specified."""
        terms = sum(x is not None for x in (self.end_time, self.duration, self.count))
        if terms != 1:
            raise ValueError("Exactly one of end_time, duration, or count must be specified")
        return self

    @model_validator(mode="after")
    def check_timing_source(self) -> "_PeriodicEventBase":
        """At least one of interval or rate must be set (subclasses enforce which)."""
        if self.interval is None and self.rate is None:
            raise ValueError("Either interval or rate must be specified")
        if self.interval is not None and self.rate is not None:
            raise ValueError("interval and rate are mutually exclusive")
        return self


class BeaconEventSpec(_PeriodicEventBase):
    """Periodic beacon — repeated connections at regular intervals.

    Produces allowed or denied connections at configurable intervals.
    Supports any protocol (HTTP/S, SSH, DNS, NTP, arbitrary).
    Replaces the former blocked_c2 event type.
    """

    type: Literal["beacon"] = "beacon"
    dst_ip: str
    dst_port: int = 443
    hostname: str | None = None  # Domain name for DNS/SSL SNI
    service: str | None = None  # ssl, http, etc.
    source_ip: str | None = None
    protocol: str = Field(default="tcp", pattern="^(tcp|udp)$")
    action: Literal["allow", "deny"] = "allow"
    # HTTP fields (when service=http)
    method: str | None = None
    uri: str | None = None
    status_code: int | None = None
    user_agent: str | None = None
    response_body_len: int | None = None
    # Override auto-sized byte counts and connection outcome
    orig_bytes: int | None = None
    resp_bytes: int | None = None
    conn_state: str | None = None

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str | None) -> str | None:
        """Validate hostname is a bare FQDN (no scheme/port/path)."""
        if v is not None:
            _validate_hostname(v, "beacon.hostname")
        return v

    @model_validator(mode="after")
    def beacon_requires_interval(self) -> "BeaconEventSpec":
        """Beacon uses interval-based timing, not rate."""
        if self.interval is None:
            raise ValueError("beacon requires interval (not rate)")
        if self.rate is not None:
            raise ValueError("beacon uses interval, not rate")
        return self


class DnsQueryEventSpec(_EventSpecBase):
    """Standalone DNS query event (generates Zeek dns.log, conn.log, Sysmon Event 22).

    Produces a single DNS query as a UDP/53 connection with DnsContext.
    Unlike connection events with causal DNS expansion, this type allows
    direct control over query parameters (qtype, rcode, ttl, answer).
    """

    type: Literal["dns_query"] = "dns_query"
    query: str  # Domain name to query
    qtype: str = "A"  # Query type: A, AAAA, TXT, CNAME, MX, NULL, SRV, PTR
    rcode: str = "NOERROR"  # Response code: NOERROR, NXDOMAIN, SERVFAIL, REFUSED
    ttl: int | None = None  # Response TTL (auto-generated if omitted)
    answer: str | list[str] | None = None  # Required when rcode=NOERROR
    source_ip: str | None = None  # Querying host IP (default: storyline system)

    @field_validator("qtype")
    @classmethod
    def validate_qtype(cls, v: str) -> str:
        """Validate query type."""
        v_upper = v.upper()
        if v_upper not in _VALID_QTYPES:
            raise ValueError(f"qtype must be one of {sorted(_VALID_QTYPES)}, got '{v}'")
        return v_upper

    @field_validator("rcode")
    @classmethod
    def validate_rcode(cls, v: str) -> str:
        """Validate response code."""
        v_upper = v.upper()
        if v_upper not in _VALID_RCODES:
            raise ValueError(f"rcode must be one of {sorted(_VALID_RCODES)}, got '{v}'")
        return v_upper

    @model_validator(mode="after")
    def answer_required_for_noerror(self) -> "DnsQueryEventSpec":
        """Answer is required when rcode is NOERROR."""
        if self.rcode == "NOERROR" and self.answer is None:
            raise ValueError("answer is required when rcode is NOERROR")
        return self


class WebScanEventSpec(_PeriodicEventBase):
    """Web scanning attack — repeated HTTP requests from scanner presets.

    Generates high-volume HTTP requests to a target web server using
    configurable presets (nikto, dirb, gobuster, sqlmap, nmap_http) or
    custom URI path lists. Each request produces web_access + Zeek HTTP logs.
    """

    type: Literal["web_scan"] = "web_scan"
    dst_ip: str
    dst_port: int = 80
    hostname: str | None = None
    source_ip: str | None = None
    preset: str | None = None  # nikto, dirb, gobuster, sqlmap, nmap_http
    paths: list[dict[str, Any]] | None = None  # [{uri, method, status}]
    user_agent: str | None = None  # Override preset UA
    status_codes: dict[str, float] | None = None  # Override status distribution

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str | None) -> str | None:
        """Validate hostname is a bare FQDN."""
        if v is not None:
            _validate_hostname(v, "web_scan.hostname")
        return v

    @model_validator(mode="after")
    def web_scan_requires_rate(self) -> "WebScanEventSpec":
        """Web scan uses rate-based timing, not interval."""
        if self.rate is None:
            raise ValueError("web_scan requires rate (not interval)")
        if self.interval is not None:
            raise ValueError("web_scan uses rate, not interval")
        return self

    @model_validator(mode="after")
    def web_scan_requires_paths_or_preset(self) -> "WebScanEventSpec":
        """Either preset or paths (or both) must be specified."""
        if self.preset is None and self.paths is None:
            raise ValueError("Either preset or paths must be specified")
        return self


class CredentialSprayEventSpec(_PeriodicEventBase):
    """Credential attack — bulk authentication attempts.

    Supports three attack patterns:
    - spray: one password per account, rotating through accounts
    - brute_force: many passwords against one account at a time
    - stuffing: one-to-one credential pairs

    Produces Windows 4625/4776 or Linux syslog auth failures depending
    on target OS, with optional final successful logon.
    """

    type: Literal["credential_spray"] = "credential_spray"
    source_ip: str | None = None
    pattern: Literal["spray", "brute_force", "stuffing"] = "spray"
    target_accounts: list[str] = Field(..., min_length=1)
    logon_type: int = 3
    success: dict[str, Any] | None = None  # {"account": str, "after": int}

    @model_validator(mode="after")
    def credential_spray_requires_interval(self) -> "CredentialSprayEventSpec":
        """Credential spray uses interval-based timing."""
        if self.interval is None:
            raise ValueError("credential_spray requires interval (not rate)")
        if self.rate is not None:
            raise ValueError("credential_spray uses interval, not rate")
        return self

    @model_validator(mode="after")
    def validate_success(self) -> "CredentialSprayEventSpec":
        """Validate success field if specified."""
        if self.success is not None:
            account = self.success.get("account")
            after = self.success.get("after")
            if not account:
                raise ValueError("success.account is required")
            if account not in self.target_accounts:
                raise ValueError(f"success.account '{account}' must be in target_accounts")
            if not isinstance(after, int) or after < 1:
                raise ValueError("success.after must be an integer >= 1")
        return self


class DgaQueriesEventSpec(_PeriodicEventBase):
    """DGA bulk DNS queries — algorithmically generated domain lookups.

    Generates many DNS queries with random domain names, mostly returning
    NXDOMAIN. Used for botnet/DGA detection training.
    """

    type: Literal["dga_queries"] = "dga_queries"
    source_ip: str | None = None
    length_range: tuple[int, int] = (8, 15)
    charset: str = "abcdefghijklmnopqrstuvwxyz0123456789"
    tld: str = ".com"
    seed: int | None = None  # Deterministic domain generation
    rcode_distribution: dict[str, float] | None = None  # {"NXDOMAIN": 0.95, "NOERROR": 0.05}
    answer_ip: str | None = None  # IP for NOERROR responses

    @field_validator("length_range")
    @classmethod
    def validate_length_range(cls, v: tuple[int, int]) -> tuple[int, int]:
        """Validate domain label length bounds."""
        lo, hi = v
        if lo < 1:
            raise ValueError("length_range minimum must be >= 1")
        if lo > hi:
            raise ValueError("length_range minimum must be <= maximum")
        if hi > 63:
            raise ValueError("length_range maximum must be <= 63 (DNS label limit)")
        return v

    @model_validator(mode="after")
    def dga_requires_interval(self) -> "DgaQueriesEventSpec":
        """DGA uses interval-based timing."""
        if self.interval is None:
            raise ValueError("dga_queries requires interval (not rate)")
        if self.rate is not None:
            raise ValueError("dga_queries uses interval, not rate")
        return self

    @model_validator(mode="after")
    def validate_rcode_distribution(self) -> "DgaQueriesEventSpec":
        """Validate rcode_distribution sums to ~1.0 and has valid keys."""
        if self.rcode_distribution is not None:
            for key in self.rcode_distribution:
                if key not in _VALID_RCODES:
                    raise ValueError(f"Invalid rcode in distribution: '{key}'")
            total = sum(self.rcode_distribution.values())
            if abs(total - 1.0) > 0.01:
                raise ValueError(f"rcode_distribution must sum to ~1.0, got {total:.3f}")
            # If any NOERROR probability, answer_ip is needed
            noerror_prob = self.rcode_distribution.get("NOERROR", 0)
            if noerror_prob > 0 and self.answer_ip is None:
                raise ValueError("answer_ip is required when rcode_distribution includes NOERROR")
        return self


class DnsTunnelEventSpec(_PeriodicEventBase):
    """DNS tunneling — data exfiltration via encoded DNS subdomain labels.

    Generates DNS queries with encoded payload chunks as subdomain labels
    (e.g., aGVsbG8gd29ybGQ.tunnel.evil.com). Supports TXT, NULL, and CNAME
    query types with base32/base64/hex encoding.
    """

    type: Literal["dns_tunnel"] = "dns_tunnel"
    source_ip: str | None = None
    base_domain: str  # Tunnel endpoint domain
    encoding: Literal["base32", "base64", "hex"] = "hex"
    qtype: str = "TXT"  # TXT, NULL, CNAME
    label_length: int = Field(default=30, ge=1, le=63)
    payload: str | None = None  # Fixed payload to encode
    payload_size: int = Field(default=256, ge=1)  # Random payload size if no payload

    @field_validator("qtype")
    @classmethod
    def validate_tunnel_qtype(cls, v: str) -> str:
        """DNS tunnel uses TXT, NULL, or CNAME query types."""
        v_upper = v.upper()
        valid = {"TXT", "NULL", "CNAME"}
        if v_upper not in valid:
            raise ValueError(f"dns_tunnel qtype must be one of {sorted(valid)}, got '{v}'")
        return v_upper

    @model_validator(mode="after")
    def dns_tunnel_requires_interval(self) -> "DnsTunnelEventSpec":
        """DNS tunnel uses interval-based timing."""
        if self.interval is None:
            raise ValueError("dns_tunnel requires interval (not rate)")
        if self.rate is not None:
            raise ValueError("dns_tunnel uses interval, not rate")
        return self


class RawEventSpec(_EventSpecBase):
    """Raw event targeting a specific emitter with arbitrary fields.

    Use for events without a dedicated typed spec (e.g., custom syslog messages,
    specific Windows events not covered by other types).
    """

    type: Literal["raw"] = "raw"
    target_format: str
    fields: dict[str, Any] = Field(default_factory=dict)
    model_config = ConfigDict(extra="forbid")


# Discriminated union of all event spec types
EventSpec = Annotated[
    ProcessEventSpec
    | LogonEventSpec
    | FailedLogonEventSpec
    | LogoffEventSpec
    | ConnectionEventSpec
    | SshSessionEventSpec
    | RdpSessionEventSpec
    | AccountCreatedEventSpec
    | AccountDeletedEventSpec
    | GroupMemberAddedEventSpec
    | ServiceInstalledEventSpec
    | ScheduledTaskCreatedEventSpec
    | LogClearedEventSpec
    | CreateRemoteThreadEventSpec
    | ProcessAccessEventSpec
    | DhcpLeaseEventSpec
    | PortScanEventSpec
    | BeaconEventSpec
    | DnsQueryEventSpec
    | WebScanEventSpec
    | CredentialSprayEventSpec
    | DgaQueriesEventSpec
    | DnsTunnelEventSpec
    | RawEventSpec,
    Discriminator("type"),
]


class StorylineEvent(BaseModel):
    """Storyline event with typed event declarations.

    Each storyline entry declares what happened (activity, for GROUND_TRUTH.md)
    and what events to generate (events list with per-type validated fields).

    Attributes:
        id: Unique event identifier (generated by scenario skill, any format)
        time: Event time (ISO 8601, relative offset like "+2h30m", or seconds "+7200")
        actor: Username of the account performing the action
        system: Target system hostname
        activity: Human-readable activity description (used in GROUND_TRUTH.md only)
        events: List of typed event declarations — each specifies type + type-specific fields
    """

    id: str = Field(..., description="Unique event identifier")
    time: str
    actor: str
    system: str
    activity: str
    events: list[EventSpec]


class RedHerringEvent(BaseModel):
    """Suspicious-but-benign event for analyst training.

    Red herrings use the same event execution path as storyline events but
    are excluded from the attack ground truth. They are documented in a
    separate "Red Herrings" section of GROUND_TRUTH.md with their explanations.

    Attributes:
        id: Unique event identifier
        time: Event time (ISO 8601, relative offset, or seconds)
        actor: Username of the account performing the action
        system: Target system hostname
        activity: Human-readable activity description (appears in Red Herrings section)
        explanation: Why this activity is benign (for instructor ground truth)
        events: List of typed event declarations
    """

    id: str = Field(..., description="Unique event identifier")
    time: str
    actor: str
    system: str
    activity: str
    explanation: str = Field(..., description="Why this is benign (for instructor ground truth)")
    events: list[EventSpec]


class Timezone(BaseModel):
    """Timezone configuration.

    Defines default timezone and optional per-system timezone overrides.
    All internal times are stored in UTC; this configuration controls
    output timezone conversions.

    Attributes:
        default: Default timezone for all systems (e.g., "UTC", "America/New_York")
        systems: Optional pattern-based timezone overrides
                 (e.g., {"WS-NYC-*": "America/New_York"})
    """

    default: str = Field(default="UTC")
    systems: dict[str, str] | None = None

    @field_validator("default")
    @classmethod
    def validate_timezone(cls, v: str) -> str:
        """Validate timezone is a valid pytz timezone."""
        try:
            pytz.timezone(v)
        except pytz.UnknownTimeZoneError as e:
            raise ValueError(f"Unknown timezone: {v}") from e
        return v

    @field_validator("systems")
    @classmethod
    def validate_system_timezones(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        """Validate per-system timezone overrides are valid pytz timezones."""
        if v is None:
            return v

        for pattern, timezone_name in v.items():
            try:
                pytz.timezone(timezone_name)
            except pytz.UnknownTimeZoneError as e:
                raise ValueError(
                    f"Unknown timezone override for pattern '{pattern}': {timezone_name}"
                ) from e
        return v


class NetworkSegment(BaseModel):
    """Network segment definition.

    Attributes:
        name: Segment identifier (e.g., "workstations", "servers", "dmz")
        cidr: CIDR notation (e.g., "10.10.10.0/24")
        description: Human-readable description
        systems: Optional list of hostnames in this segment
                 (if omitted, inferred from system IPs matching CIDR)
    """

    name: str
    cidr: str
    description: str = ""
    systems: list[str] = Field(default_factory=list)
    exposure: Literal["internal", "external", "both"] = "internal"

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        """Validate CIDR notation."""
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation: {v}") from e
        return v


class FirewallRule(BaseModel):
    """Firewall rule. Evaluated in order; first match wins.

    Default action (from NetworkSensor.default_action) applies if no rule matches.

    Attributes:
        src: Source -- segment name, "external", IP, CIDR, or "any"
        dst: Destination -- segment name, "external", IP, CIDR, or "any"
        ports: Port numbers, or empty list / "any" for all ports
        action: "permit" or "deny"
    """

    src: str
    dst: str
    ports: list[int | str] = Field(default_factory=list)
    action: str = Field(default="permit", pattern="^(permit|deny)$")


class NatRule(BaseModel):
    """NAT translation rule for firewall sensors.

    Attributes:
        type: NAT type -- "dynamic_pat" (many:1 with port translation) or "static" (1:1)
        src: Source segment name(s), IP, or CIDR. Accepts string or list for multiple segments.
        mapped_ip: Post-NAT IP address
        real_ip: For static NAT, the specific internal IP being mapped
        interface_pair: Optional [inside_iface, outside_iface] for explicit interface binding
    """

    type: str = Field(..., pattern="^(dynamic_pat|static)$")
    src: list[str] = Field(default_factory=list)
    mapped_ip: str
    real_ip: str = ""
    interface_pair: list[str] = Field(default_factory=list)

    @field_validator("src", mode="before")
    @classmethod
    def normalize_src_to_list(cls, v: str | list[str]) -> list[str]:
        """Accept a single string or a list; always store as list."""
        if isinstance(v, str):
            return [v]
        return v


class NetworkSensor(BaseModel):
    """Network sensor definition.

    Attributes:
        type: Sensor type (network|ids|firewall)
        name: Sensor identifier
        hostname: Sensor hostname used as output directory name (e.g., "fw01").
                  If unset, falls back to name.
        monitoring_segments: List of segment names this sensor monitors
        direction: Traffic direction visible (inbound|outbound|bidirectional)
        placement: How the sensor is connected (span|tap).
                   span: sees all traffic including intra-segment (e.g., SPAN port on switch)
                   tap: only sees traffic crossing segment boundaries (e.g., inline TAP on uplink)
        log_formats: Which log formats this sensor generates
        interfaces: Mapping of segment names to ASA interface names (e.g., {"dmz": "dmz",
                    "workstations": "inside"}). IPs not in any mapped segment resolve to "outside".
        policy: Ordered list of firewall rules (first match wins). Only used for firewall-type
                sensors. Default action applies if no rule matches.
        default_action: Default firewall action when no rule matches ("deny" or "permit").
        deny_ratio: For firewall sensors, ratio of deny events to generate per allow event
                    in the baseline. Default 5.0 (5 denies per allow).
        description: Optional description
    """

    type: str = Field(..., pattern="^(network|ids|firewall)$")
    name: str
    hostname: str = ""
    monitoring_segments: list[str]
    direction: str = Field(default="bidirectional", pattern="^(inbound|outbound|bidirectional)$")
    placement: str = Field(default="span", pattern="^(span|tap)$")
    log_formats: list[str] = Field(default_factory=lambda: ["zeek"])
    interfaces: dict[str, str] = Field(default_factory=dict)
    policy: list[FirewallRule] = Field(default_factory=list)
    default_action: str = Field(default="deny", pattern="^(deny|permit)$")
    deny_ratio: float = Field(
        default=5.0,
        ge=0.0,
        le=50.0,
        description=(
            "For firewall sensors, deny events generated per estimated allow event. "
            "Capped at 50.0 to prevent runaway baseline generation."
        ),
    )
    drop_mode: str = Field(default="drop", pattern="^(drop|reject)$")
    threat_detection_rate: int = Field(
        default=10,
        ge=0,
        description=(
            "Deny rate (drops/sec) that triggers 733100 threat detection alerts. "
            "Set to 0 to disable."
        ),
    )
    nat_rules: list[NatRule] = Field(default_factory=list)
    description: str = ""


class NetworkConfig(BaseModel):
    """Network topology configuration.

    Attributes:
        segments: List of network segments
        sensors: List of network sensors
    """

    segments: list[NetworkSegment]
    sensors: list[NetworkSensor]
    public_cidrs: list[str] = Field(
        default_factory=list,
        description="Public address blocks allocated to the org (e.g., ['203.0.113.0/28']). "
        "External scans/probes target these ranges. When empty, auto-derived "
        "from static NAT VIPs by grouping into /24 blocks.",
    )

    @field_validator("public_cidrs")
    @classmethod
    def validate_public_cidrs(cls, v: list[str]) -> list[str]:
        """Validate each entry is a valid CIDR."""
        for cidr in v:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid public_cidrs entry {cidr!r}: {e}") from e
        return v

    @field_validator("segments")
    @classmethod
    def validate_segments_not_empty(cls, v: list[NetworkSegment]) -> list[NetworkSegment]:
        """Ensure at least one segment is defined."""
        if not v:
            raise ValueError("Network config must have at least one segment")
        return v

    @field_validator("sensors")
    @classmethod
    def validate_sensors_not_empty(cls, v: list[NetworkSensor]) -> list[NetworkSensor]:
        """Ensure at least one sensor is defined."""
        if not v:
            raise ValueError("Network config must have at least one sensor")
        return v


class StaleAccount(BaseModel):
    """Stale/inactive account that generates background failed logon noise.

    These accounts are NOT in the active users list — they exist only to
    generate occasional failed logon events during baseline generation,
    simulating automated systems trying cached credentials that no longer work.

    Attributes:
        username: Account username (must not collide with active users or service_accounts)
        last_active: ISO date when the account was last active (for context only)
        reason: Why the account is stale (e.g., "former employee", "deprecated service")
    """

    username: str = Field(..., pattern=r"^[a-zA-Z0-9._$-]+$")
    last_active: str
    reason: str

    model_config = ConfigDict(extra="forbid")


class Environment(BaseModel):
    """Environment definition.

    Describes the computing environment including users, systems, groups,
    timezone configuration, and optional network topology.

    Attributes:
        description: Natural language environment description
        timezone: Timezone configuration (default + optional overrides)
        users: List of users (at least one required)
        systems: List of systems (at least one required)
        service_accounts: Optional list of service/system account names valid as storyline actors
        stale_accounts: Optional list of inactive accounts that generate failed logon noise
        groups: Optional list of groups
        network: Optional network topology and sensor configuration
    """

    description: str
    timezone: Timezone = Field(default_factory=lambda: Timezone(default="UTC"))
    domain: str | None = Field(
        None,
        description="Active Directory domain FQDN (e.g., corp.meridiancapital.com). "
        "Used for Computer FQDNs in Windows events and domain name fields. "
        "Auto-inferred from user emails if not specified.",
    )
    users: list[User]
    systems: list[System]
    service_accounts: list[str] = Field(
        default_factory=list,
        description="Service/system account names valid as storyline actors (e.g., svc_backup, apache)",
    )
    stale_accounts: list[StaleAccount] = Field(
        default_factory=list,
        description="Inactive accounts that generate background failed logon noise",
    )
    groups: list[Group] | None = Field(default_factory=list)
    network: NetworkConfig | None = Field(
        None, description="Optional network topology and sensor config"
    )

    @field_validator("users")
    @classmethod
    def validate_users_not_empty(cls, v: list[User]) -> list[User]:
        """Ensure at least one user is defined."""
        if not v:
            raise ValueError("Environment must have at least one user")
        return v

    @field_validator("systems")
    @classmethod
    def validate_systems_not_empty(cls, v: list[System]) -> list[System]:
        """Ensure at least one system is defined."""
        if not v:
            raise ValueError("Environment must have at least one system")
        return v


class OutputSpec(BaseModel):
    """Output specification.

    Defines what log formats to generate and where to write them.

    Attributes:
        logs: List of log format specifications (format-specific dicts)
        destination: Output directory path
        compression: Whether to compress output files
    """

    logs: list[dict[str, Any]]
    destination: str
    compression: bool = Field(default=False)


class Scenario(BaseModel):
    """Main scenario definition (simplified for Phase 1).

    Root model for a complete scenario file. Encompasses environment,
    personas, time window, baseline activity, and storyline.

    Phase 1 simplifications:
    - Personas stored as-is (no LLM expansion)
    - Storyline events stored as-is (no LLM expansion)
    - Work hours stored as strings (not parsed)
    - No semantic validation (only schema validation)

    Attributes:
        version: Scenario schema version (e.g., "1.0")
        name: Scenario name (alphanumeric, dash, underscore only)
        description: Multi-line natural language description
        environment: Environment definition
        personas: Optional list of persona definitions
        time_window: Time window for log generation
        baseline_activity: Baseline activity configuration
        storyline: Optional list of storyline events
        output: Output specification
    """

    version: str = Field(default="1.0")
    name: str = Field(..., pattern="^[a-zA-Z0-9_-]+$")
    description: str
    environment: Environment
    personas: list[Persona] | None = Field(default_factory=list)
    time_window: TimeWindow
    baseline_activity: BaselineActivity
    storyline: list[StorylineEvent] | None = Field(default_factory=list)
    red_herrings: list[RedHerringEvent] = Field(
        default_factory=list,
        description="Suspicious-but-benign events that muddy analyst attribution",
    )
    output: OutputSpec
    logon_grace_period: str = Field(
        default="30m",
        description=(
            "Duration after time_window.start during which 'no prior logon' "
            "warnings are suppressed (users assumed already logged in)"
        ),
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("logon_grace_period")
    @classmethod
    def validate_logon_grace_period(cls, v: str) -> str:
        """Validate logon_grace_period uses a valid duration format."""
        if not re.match(r"^(\d+(ms|[hdms]))+$", v):
            raise ValueError("logon_grace_period must be a duration like '30m', '1h', '2h30m'")
        return v

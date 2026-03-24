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
from typing import Annotated, Any, Literal, Optional, Union

import pytz
from pydantic import BaseModel, ConfigDict, Discriminator, Field, Tag, field_validator, model_validator


class TimeWindow(BaseModel):
    """Time window for log generation.

    Specifies when log generation should start and end. Either 'end' or 'duration'
    must be specified (but not both).

    Attributes:
        start: Start time in ISO 8601 UTC format (e.g., "2024-01-15T10:00:00Z")
        end: End time in ISO 8601 UTC format (mutually exclusive with duration)
        duration: Duration string like "10h", "3d", "2h30m" (mutually exclusive with end)
    """

    start: datetime = Field(..., description="Start time (ISO 8601 UTC)")
    end: datetime | None = Field(None, description="End time (ISO 8601 UTC)")
    duration: str | None = Field(None, description="Duration string (e.g., '10h', '3d')")

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
        username: Username (alphanumeric, dash, underscore only)
        full_name: User's full name
        email: Email address (basic format validation)
        groups: List of group names this user belongs to
        enabled: If False, user generates no activity
        persona: Reference to a persona name (if None, no activity generated)
        primary_system: Primary system hostname for this user (optional)
    """

    username: str = Field(..., pattern=r"^[a-zA-Z0-9._-]+$")
    full_name: str
    email: str
    groups: list[str] = Field(default_factory=list)
    enabled: bool = Field(default=True)
    persona: str | None = Field(None, description="Reference to persona name")
    primary_system: str | None = Field(None, description="Primary system hostname")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        """Basic email validation (format check only)."""
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", v):
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
    roles: list[str] = Field(default_factory=list, description="System roles: forward_proxy, web_server, dns_server, mail_server, etc.")

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(v)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {v}") from e
        return v



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

    # Phase 2.4 optional fields (backward compatible - prepare for future LLM expansion)
    expanded_activities: Optional[list[dict[str, Any]]] = Field(
        None,
        description="Detailed activity sequences (populated by LLM in Phase 3.1)"
    )
    work_hours_parsed: Optional[dict[str, Any]] = Field(
        None,
        description="Parsed work hours distribution (auto-populated from work_hours)"
    )
    activity_intensity: Optional[dict[str, int]] = Field(
        None,
        description="Per-activity-type intensity overrides (events/hour)"
    )

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode='after')
    def parse_work_hours_on_load(self) -> 'Persona':
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
    """

    description: str
    intensity: str = Field(..., pattern="^(low|medium|high)$")
    variation: str = Field(..., pattern="^(low|medium|high)$")

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
    """Network connection event (generates Zeek conn, eCAR FLOW, optionally Snort)."""
    type: Literal["connection"] = "connection"
    dst_ip: str
    dst_port: int = 443
    service: str | None = None  # ssl, http, etc.
    source_ip: str | None = None


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
    Union[
        ProcessEventSpec, LogonEventSpec, FailedLogonEventSpec, LogoffEventSpec,
        ConnectionEventSpec, SshSessionEventSpec, RdpSessionEventSpec,
        AccountCreatedEventSpec, AccountDeletedEventSpec, GroupMemberAddedEventSpec,
        ServiceInstalledEventSpec, ScheduledTaskCreatedEventSpec,
        LogClearedEventSpec, CreateRemoteThreadEventSpec, RawEventSpec,
    ],
    Discriminator("type"),
]


class StorylineEvent(BaseModel):
    """Storyline event with typed event declarations.

    Each storyline entry declares what happened (activity, for GROUND_TRUTH.md)
    and what events to generate (events list with per-type validated fields).

    Attributes:
        time: Event time (ISO 8601, relative offset like "+2h30m", or seconds "+7200")
        actor: Username of the account performing the action
        system: Target system hostname
        activity: Human-readable activity description (used in GROUND_TRUTH.md only)
        events: List of typed event declarations — each specifies type + type-specific fields
    """

    time: str
    actor: str
    system: str
    activity: str
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
        description: Optional description
    """

    type: str = Field(..., pattern="^(network|ids|firewall)$")
    name: str
    hostname: str = ""
    monitoring_segments: list[str]
    direction: str = Field(
        default="bidirectional", pattern="^(inbound|outbound|bidirectional)$"
    )
    placement: str = Field(default="span", pattern="^(span|tap)$")
    log_formats: list[str] = Field(default_factory=lambda: ["zeek"])
    description: str = ""



class NetworkConfig(BaseModel):
    """Network topology configuration.

    Attributes:
        segments: List of network segments
        sensors: List of network sensors
    """

    segments: list[NetworkSegment]
    sensors: list[NetworkSensor]

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
    output: OutputSpec

    model_config = ConfigDict(extra="forbid")

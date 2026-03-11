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
from typing import Any

import pytz
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
        """Validate duration format matches pattern like '10h', '3d', '2h30m'.

        Phase 1 only validates format, not semantics. Parsing into timedelta
        happens in utils/time.py.
        """
        if v is None:
            return None
        # Allow multiple digit-unit pairs like "2h30m"
        if not re.match(r"^(\d+[hdm])+$", v):
            raise ValueError(
                "Duration must match pattern like '10h', '3d', '2h30m' "
                "(digits followed by h/d/m units)"
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

    model_config = ConfigDict(extra="forbid")


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

    username: str = Field(..., pattern="^[a-zA-Z0-9_-]+$")
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

    model_config = ConfigDict(extra="forbid")


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

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(v)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {v}") from e
        return v

    model_config = ConfigDict(extra="forbid")


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

    model_config = ConfigDict(extra="forbid")


class Persona(BaseModel):
    """Persona definition (simplified for Phase 1 - no LLM expansion).

    Defines a behavioral template for user activity. In Phase 1, personas
    are stored as-is without LLM expansion. Phase 2+ will expand these
    into detailed activity plans.

    Attributes:
        name: Persona name (e.g., "developer", "accountant")
        description: Natural language behavior description
        typical_activities: List of typical activities (Phase 1: stored as strings)
        work_hours: Work hours description (Phase 1: stored as string, not parsed)
        application_usage: List of applications this persona uses
        risk_profile: Activity risk level (low|medium|high)
    """

    name: str
    description: str
    typical_activities: list[str] = Field(default_factory=list)
    work_hours: str = Field(default="9am-5pm")
    application_usage: list[str] = Field(default_factory=list)
    risk_profile: str = Field(default="medium", pattern="^(low|medium|high)$")

    model_config = ConfigDict(extra="forbid")


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


class StorylineEvent(BaseModel):
    """Storyline event (simplified for Phase 1 - no LLM expansion).

    Represents a specific event in the attack/incident storyline.
    Phase 1 stores events as-is; Phase 2+ will expand into detailed event sequences.

    Attributes:
        time: Event time (ISO 8601, relative offset like "+2h30m", or seconds "+7200")
        actor: Username or "attacker" for external actor
        system: Target system hostname
        activity: Natural language activity description
        details: Optional activity-specific details (flexible dict)
    """

    time: str
    actor: str
    system: str
    activity: str
    details: dict[str, Any] | None = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


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

    model_config = ConfigDict(extra="forbid")


class Environment(BaseModel):
    """Environment definition (simplified for Phase 1).

    Describes the computing environment including users, systems, groups,
    and timezone configuration.

    Attributes:
        description: Natural language environment description
        timezone: Timezone configuration (default + optional overrides)
        users: List of users (at least one required)
        systems: List of systems (at least one required)
        groups: Optional list of groups
    """

    description: str
    timezone: Timezone = Field(default_factory=lambda: Timezone(default="UTC"))
    users: list[User]
    systems: list[System]
    groups: list[Group] | None = Field(default_factory=list)

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

    model_config = ConfigDict(extra="forbid")


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

    model_config = ConfigDict(extra="forbid")


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

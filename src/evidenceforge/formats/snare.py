# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Developer-owned, event-specific Snare projection contracts."""

import re
from datetime import datetime
from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evidenceforge.config import get_config_directory
from evidenceforge.config.provider import _register_trusted_derived_cache
from evidenceforge.models.exceptions import ConfigurationError
from evidenceforge.utils.files import load_yaml

from .loader import load_format

LEGACY_UNAVAILABLE_FIELDS = frozenset(
    {
        "Level",
        "ExecutionProcessID",
        "ExecutionThreadID",
        "EventRecordID",
        "SubjectUserSid",
        "TargetUserSid",
        "SubjectUserName",
        "TargetUserName",
        "SubjectDomainName",
        "TargetDomainName",
        "SubjectLogonId",
        "TargetLogonId",
        "NewProcessId",
        "NewProcessName",
        "ProcessId",
        "ProcessName",
        "Status",
    }
)


class SnareEnvelope(BaseModel):
    """Native envelope requirements, independent of XML system metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    event_id: int = Field(gt=0, strict=True)
    counter: int = Field(ge=0)
    criticality: int = Field(ge=0, le=4)
    computer: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    channel: str = Field(min_length=1)
    timestamp: datetime
    logtype: Literal["Success Audit", "Failure Audit", "Error", "Information", "Warning"]


class SnareProjection(BaseModel):
    """SOF-ELK display labels and their canonical event-field owners."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    source: Literal["windows_event_security", "windows_event_sysmon"]
    event_id: int = Field(gt=0, strict=True)
    variant: str
    aliases: dict[str, str]
    decimal_aliases: dict[str, str] = Field(default_factory=dict)
    fallback_aliases: dict[str, str] = Field(default_factory=dict)


class SnareProjections(BaseModel):
    """Exhaustive packaged projection inventory."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal[1]
    events: tuple[SnareProjection, ...]

    @model_validator(mode="after")
    def check_inventory(self) -> "SnareProjections":
        seen: set[tuple[str, int]] = set()
        for event in self.events:
            identity = (event.source, event.event_id)
            if identity in seen:
                raise ValueError(f"Duplicate Snare projection: {identity}")
            seen.add(identity)
            definition = load_format(event.source)
            fields = definition.validation_fields(event.variant)
            if not fields or any(
                name not in fields
                for name in (
                    *event.aliases.values(),
                    *event.decimal_aliases.values(),
                    *event.fallback_aliases.values(),
                )
            ):
                raise ValueError(f"Invalid field reference in Snare projection: {identity}")
            if any(
                fields[name].type.value != "hex_string" for name in event.decimal_aliases.values()
            ):
                raise ValueError(f"Decimal Snare alias requires a hexadecimal owner: {identity}")
            if any(
                not re.fullmatch(r"[A-Za-z][A-Za-z0-9 ]*", label)
                for label in (*event.aliases, *event.decimal_aliases, *event.fallback_aliases)
            ):
                raise ValueError(f"Invalid Snare display label: {identity}")
            if event.fallback_aliases != {"Process ID": "ExecutionProcessID"}:
                raise ValueError(f"Unsupported Snare execution-PID fallback: {identity}")
            if event.aliases.keys() & event.decimal_aliases.keys():
                raise ValueError(f"Duplicate Snare display alias: {identity}")
            if not any(
                v.name == event.variant and int(v.event_id) == event.event_id
                for v in definition.variants
            ):
                raise ValueError(f"Snare variant does not match EventID: {identity}")
        expected = {
            (source, int(variant.event_id))
            for source in ("windows_event_security", "windows_event_sysmon")
            for variant in load_format(source).variants
        }
        if seen != expected:
            raise ValueError(f"Incomplete Snare inventory: {seen ^ expected}")
        return self


@lru_cache(maxsize=1)
def load_snare_projections() -> SnareProjections:
    """Load and validate the package-owned projection definitions."""
    return SnareProjections.model_validate(
        load_yaml(get_config_directory() / "projections" / "windows_snare.yaml")
    )


def snare_projection(source: str, event_id: int) -> SnareProjection:
    """Select a declared projection; unknown variants are configuration failures."""
    for event in load_snare_projections().events:
        if event.source == source and event.event_id == event_id:
            return event
    raise ConfigurationError(f"No Snare projection for {source} EventID {event_id}")


_register_trusted_derived_cache(
    __name__, "load_snare_projections", globals(), load_snare_projections
)

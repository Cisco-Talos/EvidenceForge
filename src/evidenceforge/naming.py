"""Shared artifact identifiers, friendly titles and portable storage names."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

SCENARIO_NAME_PATTERN = r"^[A-Za-z0-9_-]+$"
PACK_NAME_PATTERN = r"^[a-z0-9][a-z0-9-]*$"
ScenarioName = Annotated[str, Field(min_length=1, pattern=SCENARIO_NAME_PATTERN)]
PackName = Annotated[str, Field(min_length=1, pattern=PACK_NAME_PATTERN)]


class NamingRule(BaseModel):
    """Public validation rules used by the engine and generated Studio controls."""

    pattern: str
    message: str
    model_config = ConfigDict(extra="forbid", frozen=True)


NAMING_RULES = {
    "scenario": NamingRule(
        pattern=SCENARIO_NAME_PATTERN,
        message="Use letters, numbers, hyphens, or underscores; no spaces.",
    ),
    "pack": NamingRule(
        pattern=PACK_NAME_PATTERN,
        message="Use lowercase letters, digits, and hyphens; start with a letter or digit.",
    ),
}


def validate_name(name: str, kind: Literal["scenario", "pack"]) -> str:
    """Validate the full case-sensitive identifier without a presentation length limit."""
    rule = NAMING_RULES[kind]
    if re.fullmatch(rule.pattern, name) is None:
        raise ValueError(rule.message)
    return name


def validate_display_name(value: str) -> str:
    """Accept a nonblank single-line Unicode title, with spaces and punctuation."""
    if not value.strip() or any(unicodedata.category(char) in {"Cc", "Zl", "Zp"} for char in value):
        raise ValueError("Display name must be nonblank text on one line; omit it to use the name")
    return value.strip()


DisplayName = Annotated[str, AfterValidator(validate_display_name)]


def storage_name(name: str) -> str:
    """Encode a bounded, case-distinct path component while preserving the logical name."""
    if not name:
        raise ValueError("artifact name cannot be empty")
    safe = b"abcdefghijklmnopqrstuvwxyz0123456789-_"
    encoded = "".join(
        chr(byte) if byte in safe else f"%{byte:02X}" for byte in name.encode("utf-8")
    )
    return (
        encoded
        if len(encoded) <= 200
        else encoded[:64] + "-" + hashlib.sha256(name.encode()).hexdigest()
    )

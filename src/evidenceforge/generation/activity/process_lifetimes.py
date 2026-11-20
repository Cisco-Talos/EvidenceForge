# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Data-driven foreground command lifetimes shared by POSIX platforms."""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence
from decimal import Decimal, InvalidOperation
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay, merge_keyed_list

_LIFETIMES_PATH = get_activity_directory() / "process_lifetimes.yaml"
_OVERLAY_SUBPATH = "activity/process_lifetimes.yaml"
_CACHED_PROCESS_LIFETIMES: ProcessLifetimeTable | None = None


def _lowered(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(value.lower() for value in values)


class LifetimeBounds(BaseModel):
    """Inclusive lifetime range in seconds."""

    minimum: float = Field(ge=0)
    maximum: float = Field(ge=0)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_order(self) -> LifetimeBounds:
        """Require a non-reversed range."""
        if self.maximum < self.minimum:
            raise ValueError("maximum must be greater than or equal to minimum")
        return self

    def as_tuple(self) -> tuple[float, float]:
        """Return the range in the legacy ``(minimum, maximum)`` shape."""
        return (self.minimum, self.maximum)


def _bounds_from_pair(value: object) -> object:
    if isinstance(value, list | tuple) and len(value) == 2:
        return {"minimum": value[0], "maximum": value[1]}
    return value


class LifetimeCondition(BaseModel):
    """All present keys must match for the condition to hold."""

    executables: tuple[str, ...] = ()
    image_contains: tuple[str, ...] = ()
    command_starts_with: tuple[str, ...] = ()
    command_contains: tuple[str, ...] = ()
    command_has_argument: tuple[str, ...] = ()
    command_has_all_arguments: tuple[str, ...] = ()
    long_running: bool = False
    interactive_shell: bool = False

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator(
        "executables",
        "image_contains",
        "command_starts_with",
        "command_contains",
        "command_has_argument",
        "command_has_all_arguments",
    )
    @classmethod
    def lowercase_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Match case-insensitively by normalizing authored values once."""
        if any(not value for value in values):
            raise ValueError("condition values must be non-empty strings")
        return _lowered(values)

    @model_validator(mode="after")
    def require_a_predicate(self) -> LifetimeCondition:
        """Reject an empty condition, which would silently match everything."""
        if not (
            self.executables
            or self.image_contains
            or self.command_starts_with
            or self.command_contains
            or self.command_has_argument
            or self.command_has_all_arguments
            or self.long_running
            or self.interactive_shell
        ):
            raise ValueError("a lifetime condition needs at least one predicate")
        return self


class LifetimeRule(BaseModel):
    """One ordered lifetime classification."""

    id: str = Field(min_length=1)
    when: tuple[LifetimeCondition, ...] = Field(min_length=1)
    lifetime: Literal["bounded", "unbounded", "requested-sleep"] = "bounded"
    seconds: LifetimeBounds | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("seconds", mode="before")
    @classmethod
    def accept_pair(cls, value: object) -> object:
        """Accept the compact ``[minimum, maximum]`` spelling."""
        return _bounds_from_pair(value)

    @model_validator(mode="after")
    def validate_bounds(self) -> LifetimeRule:
        """Bounded and sleep rules need a range; unbounded rules must not carry one."""
        if self.lifetime == "unbounded" and self.seconds is not None:
            raise ValueError(f"rule {self.id!r} is unbounded and must not set seconds")
        if self.lifetime != "unbounded" and self.seconds is None:
            raise ValueError(f"rule {self.id!r} must set seconds")
        return self


class LongRunningCommands(BaseModel):
    """Executables and command fragments that never end on their own."""

    executables: tuple[str, ...] = ()
    command_contains: tuple[str, ...] = ()

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("executables", "command_contains")
    @classmethod
    def lowercase_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Match case-insensitively."""
        return _lowered(values)


class InteractiveShells(BaseModel):
    """Shells that are interactive when started without a command or script."""

    executables: tuple[str, ...] = Field(min_length=1)
    options: tuple[str, ...] = ()

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("executables", "options")
    @classmethod
    def lowercase_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Match case-insensitively."""
        return _lowered(values)


class ProcessLifetimeTable(BaseModel):
    """Validated, ordered POSIX foreground lifetime table."""

    schema_version: str = Field(min_length=1)
    default_seconds: LifetimeBounds
    long_running: LongRunningCommands
    command_wrappers: tuple[str, ...] = ()
    interactive_shells: InteractiveShells
    rules: tuple[LifetimeRule, ...] = Field(min_length=1)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("default_seconds", mode="before")
    @classmethod
    def accept_pair(cls, value: object) -> object:
        """Accept the compact ``[minimum, maximum]`` spelling."""
        return _bounds_from_pair(value)

    @field_validator("command_wrappers")
    @classmethod
    def lowercase_wrappers(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Match wrapper basenames case-insensitively."""
        return _lowered(values)

    @model_validator(mode="after")
    def unique_rule_ids(self) -> ProcessLifetimeTable:
        """Rule ids are overlay merge keys and must be unique."""
        ids = [rule.id for rule in self.rules]
        duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate lifetime rule ids: {', '.join(duplicates)}")
        return self


def _merge_process_lifetimes(default: dict, overlay: dict) -> dict:
    """Merge rules by id in place; other sections merge field by field."""
    result = dict(default)
    for key, value in overlay.items():
        if key == "rules":
            result["rules"] = merge_keyed_list(default.get("rules", []), value, key_field="id")
        elif key == "command_wrappers" and isinstance(value, list):
            result[key] = [*result.get(key, []), *value]
        elif isinstance(value, dict) and isinstance(result.get(key), dict):
            merged = dict(result[key])
            for field, field_value in value.items():
                existing = merged.get(field)
                if isinstance(existing, list) and isinstance(field_value, list):
                    merged[field] = [*existing, *field_value]
                else:
                    merged[field] = field_value
            result[key] = merged
        else:
            result[key] = value
    return result


def load_process_lifetimes() -> ProcessLifetimeTable:
    """Load and validate the lifetime table, merged with overlays. Cached after first call."""
    global _CACHED_PROCESS_LIFETIMES
    if _CACHED_PROCESS_LIFETIMES is not None:
        return _CACHED_PROCESS_LIFETIMES
    data = load_with_overlay(_LIFETIMES_PATH, _OVERLAY_SUBPATH, _merge_process_lifetimes)
    _CACHED_PROCESS_LIFETIMES = ProcessLifetimeTable.model_validate(data)
    return _CACHED_PROCESS_LIFETIMES


def executable_basename(process_name: str) -> str:
    """Return the lowercase image basename for either path separator."""
    return process_name.replace("\\", "/").rsplit("/", 1)[-1].lower()


_COMMAND_TOKEN_SEPARATORS = re.compile(r"[\s;|&()'\"`]+")


def is_long_running_command(process_name: str, command_line: str) -> bool:
    """Return whether a command keeps running until something else closes it."""
    long_running = load_process_lifetimes().long_running
    if executable_basename(process_name) in long_running.executables:
        return True
    command = command_line.lower()
    if any(fragment in command for fragment in long_running.command_contains):
        return True
    return any(
        executable_basename(token) in long_running.executables
        for token in _COMMAND_TOKEN_SEPARATORS.split(command)
        if token
    )


def is_interactive_shell(process_name: str, command_line: str) -> bool:
    """Return whether a POSIX shell was started without a command or script."""
    shells = load_process_lifetimes().interactive_shells
    if executable_basename(process_name) not in shells.executables:
        return False
    try:
        argv = shlex.split(command_line)
    except ValueError:
        return False
    # A login shell's argv[0] carries a leading dash (``-zsh``).
    if argv and executable_basename(argv[0]).removeprefix("-") in shells.executables:
        argv = argv[1:]
    return all(argument.lower() in shells.options for argument in argv)


def unwrapped_command(process_name: str, command_line: str) -> tuple[str, str] | None:
    """Return the program a wrapper such as ``env`` runs, or ``None`` if there is none."""
    if executable_basename(process_name) not in load_process_lifetimes().command_wrappers:
        return None
    try:
        argv = shlex.split(command_line)
    except ValueError:
        return None
    remaining = argv[1:]
    while remaining and (
        remaining[0].startswith("-")
        or ("=" in remaining[0] and not remaining[0].startswith(("/", ".")))
    ):
        remaining = remaining[1:]
    if not remaining:
        return None
    return remaining[0], shlex.join(remaining)


def numeric_sleep_seconds(arguments: Sequence[str] | None) -> Decimal | None:
    """Read one literal numeric sleep operand without executing or capping its duration."""
    if (
        arguments is None
        or len(arguments) != 2
        or arguments[0].rsplit("/", 1)[-1].lower() != "sleep"
        or re.fullmatch(r"(?:\d+(?:\.\d*)?|\.\d+)", arguments[1]) is None
    ):
        return None
    try:
        requested = Decimal(arguments[1])
    except InvalidOperation:
        return None
    return requested if requested.is_finite() and requested >= 0 else None


def _requested_sleep_lifetime(command_line: str) -> tuple[float, float] | None:
    try:
        argv = shlex.split(command_line)
    except ValueError:
        argv = []
    requested = numeric_sleep_seconds(argv)
    if requested is None:
        return None
    bounded_seconds = float(min(requested, Decimal(86_400)))
    lower = max(0.05, bounded_seconds)
    completion_slack = min(2.0, max(0.05, bounded_seconds * 0.02))
    return (lower, lower + completion_slack)


def _condition_matches(
    condition: LifetimeCondition,
    *,
    process_name: str,
    command_line: str,
) -> bool:
    exe_name = executable_basename(process_name)
    command = command_line.lower()
    padded = f" {command} "
    checks: list[bool] = []
    if condition.executables:
        checks.append(exe_name in condition.executables)
    if condition.image_contains:
        image = process_name.lower()
        checks.append(any(fragment in image for fragment in condition.image_contains))
    if condition.command_starts_with:
        checks.append(command.startswith(condition.command_starts_with))
    if condition.command_contains:
        checks.append(any(fragment in command for fragment in condition.command_contains))
    if condition.command_has_argument:
        checks.append(any(f" {arg} " in padded for arg in condition.command_has_argument))
    if condition.command_has_all_arguments:
        checks.append(all(f" {arg} " in padded for arg in condition.command_has_all_arguments))
    if condition.long_running:
        checks.append(is_long_running_command(process_name, command_line))
    if condition.interactive_shell:
        checks.append(is_interactive_shell(process_name, command_line))
    return all(checks)


def matching_lifetime_rule(process_name: str, command_line: str) -> LifetimeRule | None:
    """Return the first rule that classifies a command, if any."""
    for rule in load_process_lifetimes().rules:
        if any(
            _condition_matches(condition, process_name=process_name, command_line=command_line)
            for condition in rule.when
        ):
            return rule
    return None


def posix_command_lifetime(process_name: str, command_line: str) -> tuple[float, float] | None:
    """Return a POSIX foreground command's lifetime range, or ``None`` when unbounded."""
    wrapped = unwrapped_command(process_name, command_line)
    if wrapped is not None:
        return posix_command_lifetime(*wrapped)
    table = load_process_lifetimes()
    rule = matching_lifetime_rule(process_name, command_line)
    if rule is None:
        return table.default_seconds.as_tuple()
    if rule.lifetime == "unbounded":
        return None
    if rule.lifetime == "requested-sleep":
        requested = _requested_sleep_lifetime(command_line)
        if requested is not None:
            return requested
    if rule.seconds is None:
        raise ValueError(f"lifetime rule {rule.id!r} has no seconds range")
    return rule.seconds.as_tuple()


__all__ = [
    "InteractiveShells",
    "LifetimeBounds",
    "LifetimeCondition",
    "LifetimeRule",
    "LongRunningCommands",
    "ProcessLifetimeTable",
    "executable_basename",
    "is_interactive_shell",
    "is_long_running_command",
    "load_process_lifetimes",
    "matching_lifetime_rule",
    "numeric_sleep_seconds",
    "posix_command_lifetime",
    "unwrapped_command",
]

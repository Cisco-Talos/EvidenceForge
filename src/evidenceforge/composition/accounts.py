"""Portable authored account retirement and restoration controls."""

from __future__ import annotations

import copy
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from evidenceforge.models.scenario import User


class AccountTransition(BaseModel):
    """Select one account kind while retaining the former user's editable details."""

    model_config = ConfigDict(extra="forbid")
    username: str = Field(pattern=r"^[a-zA-Z0-9._$-]+$")
    target: Literal["users", "stale_accounts"]
    previous_user: User | None = None

    @model_validator(mode="after")
    def matching_identity(self) -> AccountTransition:
        """Keep archived details bound to the same logical account."""
        if (
            self.previous_user
            and self.previous_user.username.casefold() != self.username.casefold()
        ):
            raise ValueError("Archived user details must match the transition username")
        return self


def account_transitions(document: dict[str, Any]) -> list[AccountTransition]:
    """Validate authored controls, rejecting ambiguous duplicate identities."""
    records = TypeAdapter(list[AccountTransition]).validate_python(
        document.get("account_transitions", [])
    )
    names = [record.username.casefold() for record in records]
    if len(set(names)) != len(names):
        raise ValueError("account_transitions usernames must be unique, ignoring case")
    return records


def account_directory_effects(
    environment: dict[str, Any], username: str, *, restoring: bool
) -> list[str]:
    """Describe the reversible directory links without copying an entire inventory."""
    folded = username.casefold()
    return [
        f"{'Restore' if restoring else 'Remove'} membership in group {entry['name']}"
        for entry in environment.get("groups", []) or []
        if folded in [name.casefold() for name in entry.get("members", [])]
    ] + [
        f"{'Restore' if restoring else 'Clear'} assigned user on system {entry['hostname']}"
        for entry in environment.get("systems", []) or []
        if str(entry.get("assigned_user", "")).casefold() == folded
    ]


def apply_account_transitions(document: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Project authored account kinds and directory links before canonical validation.

    The source directory remains intact for restoration. Other references are deliberately
    retained so canonical validation can identify behavior requiring a regular account.
    """
    records = account_transitions(document)
    if not records and "account_transitions" not in document:
        return document, []
    result = copy.deepcopy(document)
    result.pop("account_transitions", None)
    environment = result.get("environment") or {}
    effects: list[str] = []
    for record in records:
        folded = record.username.casefold()
        if not any(
            str(entry.get("username", "")).casefold() == folded
            for entry in environment.get(record.target, []) or []
        ):
            raise ValueError(
                f"account_transitions: {record.username} needs a record in environment.{record.target}"
            )
        opposite = "users" if record.target == "stale_accounts" else "stale_accounts"
        environment[opposite] = [
            entry
            for entry in environment.get(opposite, []) or []
            if str(entry.get("username", "")).casefold() != folded
        ]
        if record.target != "stale_accounts":
            continue
        for group in environment.get("groups", []) or []:
            members = group.get("members", [])
            remaining = [member for member in members if member.casefold() != folded]
            if remaining != members:
                group["members"] = remaining
                effects.append(f"Remove membership in group {group['name']}")
        for system in environment.get("systems", []) or []:
            if str(system.get("assigned_user", "")).casefold() == folded:
                system["assigned_user"] = None
                effects.append(f"Clear assigned user on system {system['hostname']}")
    return result, effects

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Bounded metadata templates for well-known Windows domain policy repositories."""

from __future__ import annotations

import random
import re
from pathlib import PureWindowsPath
from string import Formatter
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from evidenceforge.generation.activity.storage_file_sizes import StorageFileSizeSupport
from evidenceforge.utils.rng import _stable_seed


def _relative_path(value: str) -> str:
    path = PureWindowsPath(value)
    if (
        not value.strip()
        or path.drive
        or path.is_absolute()
        or any(part in {"..", "."} for part in value.replace("/", "\\").split("\\"))
    ):
        raise ValueError("policy repository paths must be nonempty relative Windows paths")
    if any(character in value for character in ("\0", ":", "*", "?", '"', "<", ">", "|")):
        raise ValueError("policy repository paths contain an invalid native path character")
    return str(path)


class PolicyRepositoryFileTemplate(StorageFileSizeSupport):
    """One semantically linked relative name and bounded metadata size."""

    path: str = Field(min_length=1, max_length=220)
    mime_type: str = Field(min_length=1)
    presence_probability: float = Field(gt=0, le=1, allow_inf_nan=False, strict=True)

    @field_validator("path")
    @classmethod
    def valid_file_path(cls, value: str) -> str:
        """Reject paths that escape their GPO or logon-script repository."""
        if "{" in value or "}" in value:
            raise ValueError("policy file names must be literal paths, not templates")
        return _relative_path(value)


class PolicyRepositoryLayout(BaseModel):
    """Optional purpose-aware layout; absent configuration retains legacy catalogs."""

    enabled: bool = Field(strict=True)
    sysvol_root: str
    netlogon_root: str
    gpo_count_minimum: int = Field(ge=2, le=64, strict=True)
    gpo_count_maximum: int = Field(ge=2, le=64, strict=True)
    default_gpo_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    sysvol_files: tuple[PolicyRepositoryFileTemplate, ...] = Field(min_length=1, max_length=256)
    netlogon_files: tuple[PolicyRepositoryFileTemplate, ...] = Field(min_length=1, max_length=256)
    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("sysvol_root", "netlogon_root")
    @classmethod
    def valid_root(cls, value: str) -> str:
        """Permit only an optional domain placeholder in a relative native root."""
        for _literal, field, spec, conversion in Formatter().parse(value):
            if field is not None and (field != "domain" or spec or conversion):
                raise ValueError("policy repository roots permit only {domain}")
        return _relative_path(value)

    @field_validator("default_gpo_ids")
    @classmethod
    def valid_gpo_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Freeze native GUID spellings and reject duplicate policy identities."""
        normalized = tuple("{" + str(UUID(value.strip("{}"))).upper() + "}" for value in values)
        if len(set(normalized)) != len(normalized):
            raise ValueError("default_gpo_ids must be unique")
        return normalized

    @model_validator(mode="after")
    def coherent_layout(self) -> Self:
        """Require bounded populations and a mandatory GPO bookkeeping file."""
        if (
            self.gpo_count_maximum < self.gpo_count_minimum
            or len(self.default_gpo_ids) > self.gpo_count_minimum
        ):
            raise ValueError("GPO count bounds must be ordered and include default_gpo_ids")
        for role, files in (("sysvol", self.sysvol_files), ("netlogon", self.netlogon_files)):
            names = [file.path.casefold() for file in files]
            if len(set(names)) != len(names):
                raise ValueError(f"{role} file paths must be unique")
            if not any(file.presence_probability == 1 for file in files):
                raise ValueError(f"{role} requires at least one mandatory file")
        if not any(
            file.path.casefold() == "gpt.ini" and file.presence_probability == 1
            for file in self.sysvol_files
        ):
            raise ValueError("SYSVOL requires mandatory GPT.INI in every modeled policy")
        return self

    def root(self, role: Literal["sysvol", "netlogon"], domain: str) -> str:
        """Resolve a synthesized share root without altering explicit authored roots."""
        return (self.sysvol_root if role == "sysvol" else self.netlogon_root).format(
            domain=repository_domain(domain)
        )


def repository_domain(value: str) -> str:
    """Normalize an explicit domain before it becomes a native path component."""
    domain = value.rstrip(".").casefold()
    if (
        not domain
        or len(domain) > 253
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in domain.split(".")
        )
    ):
        raise ValueError("Windows policy repositories require a valid explicit DNS domain")
    return domain


class PolicyRepositoryFile(BaseModel):
    """One immutable automatic file candidate, with no file payload retained."""

    path: str
    size_bytes: int = Field(gt=0)
    mime_type: str
    model_config = ConfigDict(extra="forbid", frozen=True)


def policy_repository_files(
    layout: PolicyRepositoryLayout, *, role: Literal["sysvol", "netlogon"], domain: str, scope: str
) -> tuple[PolicyRepositoryFile, ...]:
    """Build a finite domain-scoped population independent of the serving DC."""
    domain = repository_domain(domain)
    rng = random.Random(_stable_seed(f"storage-policy-layout:{scope}:{domain}"))
    groups: list[tuple[str, tuple[PolicyRepositoryFileTemplate, ...]]]
    if role == "sysvol":
        count = rng.randint(layout.gpo_count_minimum, layout.gpo_count_maximum)
        identifiers = list(layout.default_gpo_ids)
        for _index in range(count - len(identifiers)):
            candidate = "{" + str(UUID(int=rng.getrandbits(128), version=4)).upper() + "}"
            identifiers.append(candidate)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("policy repository identifier collision; choose a different seed")
        groups = [
            (f"{domain}\\Policies\\{identifier}", layout.sysvol_files) for identifier in identifiers
        ]
    else:
        groups = [("", layout.netlogon_files)]
    files: list[PolicyRepositoryFile] = []
    for prefix, templates in groups:
        # Place mandatory bookkeeping first, before an optional bounded catalog cut.
        ordered = sorted(
            templates, key=lambda item: (item.path.casefold() != "gpt.ini", item.path.casefold())
        )
        for template in ordered:
            path = str(PureWindowsPath(prefix) / template.path)
            file_rng = random.Random(
                _stable_seed(f"storage-policy-file:{scope}:{domain}:{role}:{path.casefold()}")
            )
            if (
                template.presence_probability < 1
                and file_rng.random() >= template.presence_probability
            ):
                continue
            files.append(
                PolicyRepositoryFile(
                    path=path,
                    size_bytes=file_rng.randint(template.minimum_bytes, template.maximum_bytes),
                    mime_type=template.mime_type,
                )
            )
    return tuple(files)

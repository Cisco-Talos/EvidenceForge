# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed, overlay-aware resident service manager and worker profiles."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "service_process_profiles.yaml"
_OVERLAY_SUBPATH = "activity/service_process_profiles.yaml"
_CACHED_PROFILES: ServiceProcessProfilesConfig | None = None


class ServiceProcessSpec(BaseModel, extra="forbid", frozen=True):
    """Canonical metadata for one resident manager or service worker."""

    key: str = Field(min_length=1)
    image: str = Field(min_length=1)
    command_line: str = Field(min_length=1)
    username: str = Field(min_length=1)
    parent_key: str = Field(min_length=1)


class ServiceProcessFamily(BaseModel, extra="forbid", frozen=True):
    """One OS-native resident manager and its supported worker modes."""

    os_category: Literal["linux", "windows"]
    manager: ServiceProcessSpec
    workers: dict[str, ServiceProcessSpec]

    @model_validator(mode="after")
    def workers_reference_manager(self) -> ServiceProcessFamily:
        """Require every worker to descend from the family manager."""

        if not self.workers:
            raise ValueError("service process family requires at least one worker")
        invalid = sorted(
            name for name, worker in self.workers.items() if worker.parent_key != "manager"
        )
        if invalid:
            raise ValueError("service workers must use parent_key='manager': " + ", ".join(invalid))
        return self


class ServiceProcessProfilesConfig(BaseModel, extra="forbid", frozen=True):
    """Validated service manager/worker profile catalog."""

    families: dict[str, ServiceProcessFamily]


def load_service_process_profiles() -> ServiceProcessProfilesConfig:
    """Load and validate the service process catalog once per process."""

    global _CACHED_PROFILES  # noqa: PLW0603
    if _CACHED_PROFILES is None:
        raw = load_with_overlay(
            _CONFIG_PATH,
            _OVERLAY_SUBPATH,
            deep_merge_dict,
        )
        _CACHED_PROFILES = ServiceProcessProfilesConfig.model_validate(raw)
    return _CACHED_PROFILES


def service_process_family(name: str) -> ServiceProcessFamily:
    """Return one named service process family."""

    try:
        return load_service_process_profiles().families[name]
    except KeyError as exc:
        raise KeyError(f"unknown service process family {name!r}") from exc


def matching_service_worker(
    *,
    os_category: str,
    image: str,
    command_line: str,
    username: str,
) -> tuple[str, str, ServiceProcessFamily] | None:
    """Return an exact configured worker match for a generic process request."""

    normalized_image = image.replace("/", "\\").casefold()
    for family_name, family in load_service_process_profiles().families.items():
        if family.os_category != os_category:
            continue
        for worker_name, worker in family.workers.items():
            worker_image = worker.image.replace("/", "\\").casefold()
            if worker_image != normalized_image:
                continue
            if worker.command_line != command_line or worker.username != username:
                continue
            return family_name, worker_name, family
    return None

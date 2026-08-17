# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed deployment boundary for Linux systemd timer and cron catalogs."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay, merge_keyed_list
from evidenceforge.config.schemas import SystemdScheduleEntry
from evidenceforge.utils.rng import _stable_seed

_CONFIG_PATH = get_activity_directory() / "systemd_schedules.yaml"
_OVERLAY_SUBPATH = "activity/systemd_schedules.yaml"
_CACHED_SCHEDULES: tuple[SystemdScheduleEntry, ...] | None = None
_CACHED_SCHEDULES_BY_ID: dict[str, SystemdScheduleEntry] | None = None


def _merge_systemd_schedules(default: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge schedule overlays by their stable source-native service name."""

    result = dict(default)
    if "schedules" in overlay:
        result["schedules"] = merge_keyed_list(
            default.get("schedules", []),
            overlay["schedules"],
            key_field="service",
        )
    return result


def load_systemd_schedule_descriptors() -> tuple[SystemdScheduleEntry, ...]:
    """Load and validate every Linux schedule descriptor once."""

    global _CACHED_SCHEDULES
    if _CACHED_SCHEDULES is None:
        raw = load_with_overlay(_CONFIG_PATH, _OVERLAY_SUBPATH, _merge_systemd_schedules)
        schedules = tuple(
            SystemdScheduleEntry.model_validate(entry) for entry in raw.get("schedules", ())
        )
        seen_ids: set[str] = set()
        for schedule in schedules:
            if schedule.id is None:  # pragma: no cover - compatibility normalizer supplies it
                raise ValueError("Linux schedule deployment descriptor requires an id")
            if schedule.id in seen_ids:
                raise ValueError(f"duplicate Linux schedule deployment id {schedule.id!r}")
            seen_ids.add(schedule.id)
        _CACHED_SCHEDULES = schedules
    return _CACHED_SCHEDULES


def systemd_schedule_descriptor(schedule_id: str) -> SystemdScheduleEntry | None:
    """Return one exact Linux schedule descriptor without scanning the catalog."""

    global _CACHED_SCHEDULES_BY_ID
    if _CACHED_SCHEDULES_BY_ID is None:
        _CACHED_SCHEDULES_BY_ID = {
            schedule.id: schedule
            for schedule in load_systemd_schedule_descriptors()
            if schedule.id is not None
        }
    return _CACHED_SCHEDULES_BY_ID.get(schedule_id)


def ordered_systemd_schedule_descriptors(
    schedule_ids: Iterable[str],
) -> tuple[SystemdScheduleEntry, ...]:
    """Resolve exact deployed schedule IDs in authored catalog order."""

    requested = frozenset(schedule_ids)
    if not requested:
        return ()
    return tuple(
        schedule for schedule in load_systemd_schedule_descriptors() if schedule.id in requested
    )


def _normalized(values: Iterable[str]) -> set[str]:
    return {value.strip().casefold().replace("-", "_") for value in values if value.strip()}


def _is_rhel_like(os_name: str) -> bool:
    normalized = os_name.casefold()
    return any(name in normalized for name in ("centos", "rhel", "red hat", "rocky", "alma"))


def schedule_applies_to_host(
    schedule: SystemdScheduleEntry,
    *,
    hostname: str,
    os_name: str,
    roles: Iterable[str],
    services: Iterable[str],
) -> bool:
    """Return whether a schedule is installed on one exact modeled Linux host."""

    rhel_like = _is_rhel_like(os_name)
    if schedule.distro == "debian" and rhel_like:
        return False
    if schedule.distro == "rhel" and not rhel_like:
        return False
    host_roles = _normalized(roles)
    host_services = _normalized(services)
    required_roles = _normalized(schedule.roles or ())
    if schedule.role:
        required_roles.add(schedule.role.casefold().replace("-", "_"))
    if required_roles and host_roles.isdisjoint(required_roles):
        return False
    excluded_roles = _normalized(schedule.exclude_roles or ())
    if excluded_roles and not host_roles.isdisjoint(excluded_roles):
        return False
    required_services = _normalized(schedule.services_any or ())
    if required_services and host_services.isdisjoint(required_services):
        return False
    probability = schedule.host_probability
    if probability is None or probability >= 1.0:
        return True
    if probability <= 0.0:
        return False
    bucket = (_stable_seed(f"sched_host_enabled:{hostname}:{schedule.service}") % 10_000) / 10_000
    return bucket < probability


def deployed_systemd_schedule_descriptors(
    *,
    hostname: str,
    os_name: str,
    roles: Iterable[str],
    services: Iterable[str],
) -> tuple[SystemdScheduleEntry, ...]:
    """Return the deterministic installed Linux task set for one host."""

    return tuple(
        schedule
        for schedule in load_systemd_schedule_descriptors()
        if schedule_applies_to_host(
            schedule,
            hostname=hostname,
            os_name=os_name,
            roles=roles,
            services=services,
        )
    )


def schedule_deployment_paths(
    schedule: SystemdScheduleEntry,
    *,
    os_name: str,
) -> tuple[str, ...]:
    """Return exact executable paths admitted by one selected schedule."""

    paths: list[str] = []
    if schedule.process_path:
        paths.append(schedule.process_path)
    by_distro = schedule.deployment_paths_by_distro or {}
    paths.extend(by_distro.get("all", ()))
    paths.extend(by_distro.get("rhel" if _is_rhel_like(os_name) else "debian", ()))
    return tuple(dict.fromkeys(path for path in paths if path))

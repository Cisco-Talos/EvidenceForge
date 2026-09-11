# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed, overlay-aware SMB client and server process profiles."""

from __future__ import annotations

import posixpath
import random
from collections.abc import Iterable
from dataclasses import dataclass
from string import Formatter
from typing import Literal

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.config.schemas import (
    SmbClientProfile,
    SmbFileEvolutionProfile,
    SmbProcessProfile,
    SmbProfilesConfig,
    SmbSambaAuditOperation,
    SmbServerProfile,
)
from evidenceforge.utils.rng import _stable_seed

_CONFIG_PATH = get_activity_directory() / "smb_profiles.yaml"
_OVERLAY_SUBPATH = "activity/smb_profiles.yaml"
_CACHED_PROFILES: SmbProfilesConfig | None = None
_ALLOWED_RENDER_FIELDS = frozenset(
    {
        "server",
        "share",
        "path",
        "client_path",
        "local_path",
        "source_path",
        "destination_path",
        "username",
        "smb_principal",
        "auth_options",
        "operation",
        "client_ip",
    }
)


@dataclass(frozen=True, slots=True)
class RenderedSmbProcess:
    """Concrete process metadata rendered from one immutable SMB profile."""

    key: str
    image: str
    command_line: str
    username: str
    lifecycle: str


def load_smb_profiles() -> SmbProfilesConfig:
    """Load and validate SMB profiles, merged with a project-local overlay."""

    global _CACHED_PROFILES  # noqa: PLW0603
    if _CACHED_PROFILES is None:
        raw = load_with_overlay(
            _CONFIG_PATH,
            _OVERLAY_SUBPATH,
            deep_merge_dict,
        )
        _CACHED_PROFILES = SmbProfilesConfig.model_validate(raw)
    return _CACHED_PROFILES


def reset_smb_profiles_cache() -> None:
    """Clear cached SMB profile data. Intended for tests and provider isolation."""

    global _CACHED_PROFILES  # noqa: PLW0603
    _CACHED_PROFILES = None


def smb_file_evolution_profile(extension: str) -> SmbFileEvolutionProfile:
    """Return the configured bounded size profile for one file extension."""

    config = load_smb_profiles().file_evolution
    normalized = extension.strip().casefold()
    profile_name = config.extension_profiles.get(normalized, config.default_profile)
    return config.profiles[profile_name]


def advertised_filesystem_default(platform: str, backing_filesystem: str) -> str:
    """Return the configured SMB wire label for one platform/backing pair."""

    normalized_platform = _normalize_os_category(platform)
    normalized_backing = backing_filesystem.strip().casefold()
    defaults = load_smb_profiles().advertised_filesystem_defaults
    platform_defaults = defaults.windows if normalized_platform == "windows" else defaults.linux
    try:
        return platform_defaults[normalized_backing]
    except KeyError as exc:
        raise KeyError(
            "no advertised SMB filesystem default for "
            f"platform={normalized_platform!r}, backing_filesystem={normalized_backing!r}"
        ) from exc


def get_samba_audit_operation(event_type: str) -> SmbSambaAuditOperation | None:
    """Return configured Samba audit metadata for one canonical event type."""

    return load_smb_profiles().samba_audit.operations.get(event_type.strip().casefold())


def samba_audit_enabled(event_type: str, audit_profile: str, result: str) -> bool:
    """Return whether one canonical SMB event is visible in Samba VFS audit."""

    operation = get_samba_audit_operation(event_type)
    if operation is None:
        return False
    normalized_profile = audit_profile.strip().casefold()
    if normalized_profile not in {"minimal", "standard", "high"}:
        raise ValueError(f"unsupported Samba audit profile {audit_profile!r}")
    if normalized_profile == "minimal":
        # Minimal is a lifecycle-only source profile. Keep this as a runtime
        # invariant in addition to schema validation so no file result can be
        # promoted by configuration.
        return False
    config = load_smb_profiles().samba_audit
    if (
        result.strip().casefold() != "success"
        and normalized_profile in config.failure_audit_profiles
    ):
        return True
    return normalized_profile in operation.audit_profiles


def get_client_profile(name: str) -> SmbClientProfile:
    """Return one named SMB client profile or raise an actionable error."""

    profiles = load_smb_profiles().client_profiles
    try:
        return profiles[name]
    except KeyError as exc:
        raise KeyError(f"unknown SMB client profile {name!r}") from exc


def client_profile(name: str) -> SmbClientProfile:
    """Return one named SMB client profile."""

    return get_client_profile(name)


def eligible_client_profiles(
    os_category: str,
    *,
    system_type: str | None = None,
) -> tuple[SmbClientProfile, ...]:
    """Return configured client profiles eligible for a platform and host type."""

    normalized_os = _normalize_os_category(os_category)
    normalized_type = system_type.casefold() if system_type else None
    return tuple(
        profile
        for _name, profile in sorted(load_smb_profiles().client_profiles.items())
        if profile.os_category == normalized_os
        and (normalized_type is None or normalized_type in profile.system_types)
    )


def select_client_profile(
    os_category: str,
    services: Iterable[str],
    system_type: str | None = None,
    access_mode: str | None = None,
    scope_key: str = "",
) -> SmbClientProfile:
    """Select a deterministic client profile from explicit services or the OS default.

    An explicit ``access_mode`` has highest precedence. Otherwise, service aliases
    select matching profiles. Generic ``smb``/``smb-client`` capabilities do not
    match a mode and therefore resolve to the configured platform default.
    """

    normalized_os = _normalize_os_category(os_category)
    normalized_services = frozenset(
        str(service).strip().casefold() for service in services if str(service).strip()
    )
    normalized_type = system_type.casefold() if system_type else None
    named_candidates = [
        (name, profile)
        for name, profile in sorted(load_smb_profiles().client_profiles.items())
        if profile.os_category == normalized_os
        and (normalized_type is None or normalized_type in profile.system_types)
    ]
    if access_mode is not None:
        normalized_mode = access_mode.casefold()
        mode_matches = [
            candidate
            for candidate in named_candidates
            if candidate[1].access_mode == normalized_mode
        ]
        if not mode_matches:
            raise ValueError(
                f"no SMB client profile for os_category={normalized_os!r}, "
                f"access_mode={access_mode!r}, system_type={system_type!r}"
            )
        return _select_weighted_client_profile(
            mode_matches,
            scope_key=f"mode:{normalized_os}:{normalized_mode}:{scope_key}",
        )

    service_matches = [
        candidate
        for candidate in named_candidates
        if normalized_services.intersection(candidate[1].service_aliases)
    ]
    if service_matches:
        return _select_weighted_client_profile(
            service_matches,
            scope_key=(
                f"service:{normalized_os}:{','.join(sorted(normalized_services))}:{scope_key}"
            ),
        )

    config = load_smb_profiles()
    default_name = config.client_defaults[normalized_os]
    return config.client_profiles[default_name]


def get_server_profile(name: str) -> SmbServerProfile:
    """Return one named SMB server profile or raise an actionable error."""

    profiles = load_smb_profiles().server_profiles
    try:
        return profiles[name]
    except KeyError as exc:
        raise KeyError(f"unknown SMB server profile {name!r}") from exc


def server_profile(name: str) -> SmbServerProfile:
    """Return one named SMB server profile."""

    return get_server_profile(name)


def select_server_profile(
    os_category: str,
    services: Iterable[str] = (),
) -> SmbServerProfile:
    """Select a server profile by platform and service alias, then use its OS default."""

    normalized_os = _normalize_os_category(os_category)
    normalized_services = frozenset(
        str(service).strip().casefold() for service in services if str(service).strip()
    )
    config = load_smb_profiles()
    matches = [
        profile
        for _name, profile in sorted(config.server_profiles.items())
        if profile.os_category == normalized_os
        and normalized_services.intersection(profile.service_aliases)
    ]
    if matches:
        return matches[0]
    return config.server_profiles[config.server_defaults[normalized_os]]


def client_process_for_operation(
    profile: SmbClientProfile,
    operation: str,
    *,
    transfer_direction: Literal["download", "upload", "remote"] | None = None,
) -> SmbProcessProfile | None:
    """Return the operation-specific client actor, including transfer direction."""

    if transfer_direction not in {None, "download", "upload", "remote"}:
        raise ValueError(f"unsupported SMB transfer direction {transfer_direction!r}")
    process_operation = operation
    if operation in {"copy", "move"}:
        if profile.access_mode == "mounted":
            # Mounted paths are ordinary local filesystem operands. Keep the
            # authored copy/move tool and let the resolved source/destination
            # views determine direction; mapping uploads to `create` would
            # incorrectly turn cp/mv into touch.
            process_operation = operation
        elif transfer_direction == "upload":
            process_operation = "create"
        elif transfer_direction == "download":
            process_operation = "copy"
        elif transfer_direction == "remote" and operation == "move":
            process_operation = "move"

    operation_process = profile.operation_processes.get(process_operation)
    if profile.access_mode == "mounted":
        if operation_process is None:
            raise ValueError(
                "mounted SMB client profile has no explicit operation actor for "
                f"{process_operation!r}"
            )
        return operation_process
    return operation_process or profile.process


def local_smbclient_operand(remote_path: str, explicit_local_path: str = "") -> str:
    """Return a local smbclient operand, never a second remote share presentation."""

    candidate = explicit_local_path.strip()
    normalized = candidate.replace("\\", "/").casefold()
    if normalized.startswith("//") or normalized.startswith("smb://"):
        candidate = ""
    if candidate:
        return candidate

    basename = posixpath.basename(remote_path.replace("\\", "/").rstrip("/"))
    if not basename:
        raise ValueError("SMB client operation requires a file-like remote path")
    return basename


def client_auth_options(profile: SmbClientProfile, auth_protocol: str) -> str:
    """Return source-native client flags for one resolved SMB auth protocol."""

    if not profile.auth_options:
        return ""
    normalized = auth_protocol.strip().casefold() or "auto"
    try:
        return profile.auth_options[normalized]
    except KeyError as exc:
        raise ValueError(f"unsupported SMB client auth protocol {auth_protocol!r}") from exc


def render_process(
    profile: SmbProcessProfile,
    **values: str,
) -> RenderedSmbProcess:
    """Render concrete process metadata from an already validated profile template."""

    unknown_values = sorted(set(values) - _ALLOWED_RENDER_FIELDS)
    if unknown_values:
        raise ValueError(f"unsupported SMB process render values: {unknown_values}")
    rendered_values: dict[str, str] = {field: str(value) for field, value in values.items()}
    if "smb_principal" not in rendered_values and "username" in rendered_values:
        # Opaque/background SMB callers have no independently modeled credential.
        # Their only defensible fallback is the local process owner; canonical
        # smb_activity always supplies its already-resolved SMB principal.
        rendered_values["smb_principal"] = rendered_values["username"]
    required = set()
    for template in (
        profile.key_template,
        profile.command_line_template,
        profile.username_template,
    ):
        required.update(
            placeholder
            for _literal, placeholder, _format_spec, _conversion in Formatter().parse(template)
            if placeholder is not None
        )
    missing = sorted(required - set(rendered_values))
    if missing:
        raise ValueError(f"missing SMB process render values: {missing}")
    return RenderedSmbProcess(
        key=profile.key_template.format_map(rendered_values),
        image=profile.image,
        command_line=profile.command_line_template.format_map(rendered_values),
        username=profile.username_template.format_map(rendered_values),
        lifecycle=profile.lifecycle,
    )


def _select_weighted_client_profile(
    candidates: list[tuple[str, SmbClientProfile]],
    *,
    scope_key: str,
) -> SmbClientProfile:
    """Select one weighted profile with a scope-local deterministic RNG."""

    if len(candidates) == 1:
        return candidates[0][1]
    rng = random.Random(_stable_seed(f"smb-client-profile:{scope_key}"))
    profiles = [profile for _name, profile in candidates]
    return rng.choices(profiles, weights=[profile.weight for profile in profiles], k=1)[0]


def _normalize_os_category(os_category: str) -> str:
    """Normalize and validate a supported SMB endpoint platform."""

    normalized = os_category.strip().casefold()
    if normalized not in {"windows", "linux"}:
        raise ValueError(f"unsupported SMB os_category {os_category!r}")
    return normalized

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Frozen synthetic installed-file provisioning policy with ordinary overlays."""

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.config.provider import current_effective_config
from evidenceforge.config.schemas import MacosInstalledFileProfile

_CACHED_PROFILE: MacosInstalledFileProfile | None = None


def load_macos_installed_file_profile() -> MacosInstalledFileProfile | None:
    """Load the modeled policy through the current immutable effective config."""
    global _CACHED_PROFILE
    effective = current_effective_config()
    if (
        effective is not None
        and not effective.ambient_overlay_compat
        and "activity/macos_installed_files.yaml" not in effective.packaged_defaults
    ):
        # Older published inputs cannot silently acquire today's new policy.
        return None
    if _CACHED_PROFILE is None:
        _CACHED_PROFILE = MacosInstalledFileProfile.model_validate(
            load_with_overlay(
                get_activity_directory() / "macos_installed_files.yaml",
                "activity/macos_installed_files.yaml",
                deep_merge_dict,
            )
        )
    return _CACHED_PROFILE

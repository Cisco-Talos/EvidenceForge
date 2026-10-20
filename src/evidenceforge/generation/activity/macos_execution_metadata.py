# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Frozen modeled Mac execution/device policy through ordinary overlays."""

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.config.provider import current_effective_config
from evidenceforge.config.schemas import MacosExecutionMetadataProfile

_CACHED_PROFILE: MacosExecutionMetadataProfile | None = None


def load_macos_execution_metadata_profile() -> MacosExecutionMetadataProfile | None:
    """Load explicit policy without adding new defaults to older frozen inputs."""
    global _CACHED_PROFILE
    effective = current_effective_config()
    if (
        effective is not None
        and not effective.ambient_overlay_compat
        and "activity/macos_execution_metadata.yaml" not in effective.packaged_defaults
    ):
        return None
    if _CACHED_PROFILE is None:
        _CACHED_PROFILE = MacosExecutionMetadataProfile.model_validate(
            load_with_overlay(
                get_activity_directory() / "macos_execution_metadata.yaml",
                "activity/macos_execution_metadata.yaml",
                deep_merge_dict,
            )
        )
    return _CACHED_PROFILE

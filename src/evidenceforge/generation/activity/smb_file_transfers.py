# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""SMB file-transfer realism configuration loader."""

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "smb_file_transfers.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_smb_file_transfers(default: dict, overlay: dict) -> dict:
    """Merge SMB file-transfer overlay with package defaults."""
    return deep_merge_dict(default, overlay)


def load_smb_file_transfers() -> dict[str, Any]:
    """Load SMB file-transfer config from YAML, merged with overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA

    _CACHED_DATA = load_with_overlay(
        _CONFIG_PATH,
        "activity/smb_file_transfers.yaml",
        _merge_smb_file_transfers,
    )
    return _CACHED_DATA


def reset_smb_file_transfers_cache() -> None:
    """Clear cached SMB file-transfer config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None

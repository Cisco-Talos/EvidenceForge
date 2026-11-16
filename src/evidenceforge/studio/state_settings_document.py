"""Lightweight settings-envelope decoding shared by recovery and uninstall."""

from __future__ import annotations

from evidenceforge.studio.state_io import StudioStateError


def decode_settings_document(raw: dict[str, object]) -> tuple[int, dict[str, object]]:
    """Validate a settings envelope independently of its caller's file-read policy."""
    version = raw.get("schema_version", 0)
    if type(version) is not int or version not in (0, 1, 2, 3, 4):
        raise StudioStateError(
            f"Unsupported Studio settings version {version}; use a compatible release"
        )
    if version >= 1:
        if set(raw) != {"schema_version", "settings"} or not isinstance(raw["settings"], dict):
            raise StudioStateError("Invalid versioned Studio settings envelope")
        values = raw["settings"]
    else:
        values = raw
    if version == 2:
        from evidenceforge.studio.state_records_v3 import StudioSettings
    elif version == 3:
        from evidenceforge.studio.state_settings_v3 import StudioSettings
    elif version == 4:
        from evidenceforge.studio.state_settings_v4 import StudioSettings
    else:
        from evidenceforge.studio.state_records_v1 import StudioSettings
    StudioSettings.model_validate(values)
    return version, values

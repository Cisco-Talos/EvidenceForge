"""Frozen settings-v4 reader after automatic bounded-memory evaluation."""

from evidenceforge.studio.state_records_v3 import StudioSettings as StudioSettingsV2


class StudioSettings(StudioSettingsV2):
    """Settings v4 no longer carries the retired corpus-size override."""

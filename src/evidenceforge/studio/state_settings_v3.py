"""Frozen settings-v3 reader, independent of future preference changes."""

from evidenceforge.studio.state_records_v3 import StudioSettings as StudioSettingsV2


class StudioSettings(StudioSettingsV2):
    """Settings v3 permits large evaluations by default."""

    allow_large_evaluation: bool = True

"""Shared document envelopes and schema evolution, independent of every interface."""

from .contracts import (
    LIFECYCLE_FIELDS,
    DocumentContract,
    LifecycleMetadata,
    ParentReference,
    identify_document,
    scenario_payload,
)
from .upgrades import update_top_level, upgrade_sources

__all__ = [
    "LIFECYCLE_FIELDS",
    "DocumentContract",
    "LifecycleMetadata",
    "ParentReference",
    "identify_document",
    "scenario_payload",
    "update_top_level",
    "upgrade_sources",
]

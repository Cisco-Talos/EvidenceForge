"""Supplementary Studio grouping over shared, authoritative file ancestry."""

from __future__ import annotations

import logging

from evidenceforge.artifacts.lineage import (
    ArtifactGroup,
    ArtifactLineage,
    group_lineage,
    inspect_lineage,
)
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.studio.store import CatalogItem

logger = logging.getLogger(__name__)


def inspect_groups(items: list[CatalogItem]) -> dict[str, ArtifactGroup]:
    """Keep repairable files visible even when their exact ancestry cannot be inspected."""
    records: dict[str, ArtifactLineage] = {}
    for item in items:
        try:
            records[item.id] = inspect_lineage(item.path)
        except (EvidenceForgeError, OSError, ValueError, TypeError, AttributeError) as exc:
            logger.debug(
                "Cannot inspect library ancestry for %s (%s)", item.path, type(exc).__name__
            )
    return group_lineage(records)

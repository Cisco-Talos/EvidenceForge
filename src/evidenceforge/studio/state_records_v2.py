"""Frozen database version 2 naming additions; version 1 readers remain unchanged."""

from __future__ import annotations

from evidenceforge.studio.state_records_v1 import CatalogItem as CatalogItemV1
from evidenceforge.studio.state_records_v1 import Conversation as ConversationV1


class CatalogItem(CatalogItemV1):
    """A derived title copied from portable artifact sources."""

    display_name: str | None = None


class Conversation(ConversationV1):
    """A title offered before a scenario file has been authored."""

    draft_display_name: str | None = None

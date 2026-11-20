"""Frozen database version 5 library-view records; earlier readers remain unchanged."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from evidenceforge.studio.state_records_v1 import LibraryPreferences as LibraryPreferencesV1
from evidenceforge.studio.state_records_v1 import LibraryView as LibraryViewV1
from evidenceforge.studio.state_records_v1 import SavedView as SavedViewV1


class SavedView(SavedViewV1):
    """Named views may also group packs by publisher."""

    sort: Literal["name", "updated", "project", "publisher"] = "name"


class LibraryView(LibraryViewV1):
    """Libraries open grouped; `publisher` grouping applies to packs only."""

    sort: Literal["name", "updated", "project", "publisher"] = "project"


class LibraryPreferences(LibraryPreferencesV1):
    """New workspaces open scenarios grouped by project and packs by publisher."""

    scenarios: LibraryView = Field(default_factory=LibraryView)
    packs: LibraryView = Field(default_factory=lambda: LibraryView(sort="publisher"))

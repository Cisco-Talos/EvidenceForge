"""Changes to persisted SQL/JSON models require an explicit versioned contract update."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel

from evidenceforge.desktop import job_store, state
from evidenceforge.studio import settings, store
from evidenceforge.studio import state_records_v1 as frozen
from evidenceforge.studio import state_records_v2 as frozen_v2
from evidenceforge.studio import state_records_v3 as frozen_v3

MODELS = (
    (store.CatalogItem, frozen_v2.CatalogItem),
    (store.Project, frozen.Project),
    (store.ImportedBundle, frozen.ImportedBundle),
    (store.Conversation, frozen_v2.Conversation),
    (store.SavedView, frozen.SavedView),
    (store.LibraryView, frozen.LibraryView),
    (store.LibraryPreferences, frozen.LibraryPreferences),
    (state.GenerationJob, frozen.GenerationJob),
    (state.EvaluationJob, frozen.EvaluationJob),
    (state.AppSettings, frozen.AppSettings),
    (job_store.ControlIntent, frozen.ControlIntent),
    (settings.QuitSettings, frozen.QuitSettings),
    (settings.StudioSettings, frozen_v3.StudioSettings),
)
IDENTITY_FACTORIES = {"id", "updated_at", "workspace"}


def normalize_schema(value: Any) -> Any:
    """Remove documentation and deliberately frozen identity-factory annotations only."""
    if isinstance(value, list):
        return [normalize_schema(entry) for entry in value]
    if not isinstance(value, dict):
        return value
    normalized = {
        key: normalize_schema(item)
        for key, item in value.items()
        if not (key in {"title", "description"} and isinstance(item, str))
    }
    if isinstance(normalized.get("properties"), dict):
        for name in IDENTITY_FACTORIES:
            if name in normalized["properties"]:
                normalized["properties"][name].pop("default", None)
    return normalized


@pytest.mark.parametrize(
    "current,historical", MODELS, ids=[current.__name__ for current, _ in MODELS]
)
def test_current_saved_record_schema_matches_frozen_version(
    current: type[BaseModel], historical: type[BaseModel]
) -> None:
    assert normalize_schema(current.model_json_schema()) == normalize_schema(
        historical.model_json_schema()
    ), "Persisted record fields changed: add a database/settings migration and a new frozen reader"
    for name, field in current.model_fields.items():
        if name in IDENTITY_FACTORIES:
            continue
        actual = field.get_default(call_default_factory=True)
        expected = historical.model_fields[name].get_default(call_default_factory=True)
        if isinstance(actual, BaseModel):
            actual = actual.model_dump(mode="json")
            expected = expected.model_dump(mode="json")
        assert actual == expected, (
            f"Persisted default changed without a migration: {current.__name__}.{name}"
        )


def test_released_migration_fingerprints_remain_unchanged() -> None:
    from evidenceforge.studio.state_database import MIGRATIONS
    from evidenceforge.studio.state_migrations import LAYOUT_MIGRATIONS, SETTINGS_MIGRATIONS

    frozen_checksums = {
        "studio-db-0001": "8752d97b66d3b778ce85b7e62a4dea5afb38ace4da19cf21933d1b86b5c6513a",
        "studio-db-0002": "1cd7133738ba7d63f0f211a71028a32e6766a12aa277b25555962545f3466da1",
        "studio-settings-0001": "9b86af96a4cb65493729f8101c9fdda3ca988ae6f3b78553cb7c79211a9581d0",
        "studio-private-layout-0001": "d97b4514e891b0eb7541f3c858ca725d8a542b9b97c5f3cf8004f979c9576403",
        "studio-workspace-layout-0001": "08a95224ef8faef04021e1c2a153ef9caae7fc327e378cbf127192bd3c7b4245",
    }
    declarations = {
        entry.id: entry.checksum
        for entry in (*MIGRATIONS, *SETTINGS_MIGRATIONS, *LAYOUT_MIGRATIONS)
    }
    assert {identity: declarations[identity] for identity in frozen_checksums} == frozen_checksums

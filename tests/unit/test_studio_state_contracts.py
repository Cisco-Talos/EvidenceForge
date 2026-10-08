"""Changes to persisted SQL/JSON models require an explicit versioned contract update."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel

from evidenceforge.desktop import job_store, state
from evidenceforge.studio import settings, store
from evidenceforge.studio import state_records_v1 as frozen
from evidenceforge.studio import state_records_v2 as frozen_v2

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
    (settings.StudioSettings, frozen.StudioSettings),
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

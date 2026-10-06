"""Contextual substring results, deterministic ranking, and persisted display limits."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from evidenceforge.studio.service import create_app
from evidenceforge.studio.settings import SettingsStore, StudioSettings
from tests.unit.test_studio_service import _paths, _scenario


def test_search_ranks_values_before_keys_and_lists_extra_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    source = _scenario(workspace, "lookup")
    source.write_text(
        source.read_text()
        + "network_identities:\n  label: workstations\nnotes:\n"
        + "".join(f"  field{i}: work value {i}\n" for i in range(7))
        + "# work comment\n"
    )
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    paths = _paths(tmp_path / "app")
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(paths, "secret")) as client:
        settings = client.get("/v1/settings", headers=headers).json()
        assert settings["search_match_limit"] == 5
        result = client.get("/v1/items?kind=scenario&search=work", headers=headers).json()[0]
        assert len(result["search_matches"]) == 5
        assert result["search_match_count"] == 10
        match = result["search_matches"][0]
        assert match["kind"] == "value"
        assert match["field"] == "network_identities.label"
        assert match["file"] == "scenario.yaml"
        assert match["line"] == 7
        assert match["excerpt"] == "workstations"
        assert match["highlights"] == [[0, 4]]
        settings["search_match_limit"] = 12
        assert client.put("/v1/settings", headers=headers, json=settings).status_code == 200
        all_matches = client.get("/v1/items?kind=scenario&search=work", headers=headers).json()[0]
        assert len(all_matches["search_matches"]) == 10
        assert all_matches["search_matches"][-2]["kind"] == "key"
        assert all_matches["search_matches"][-2]["excerpt"] == "network_identities"
        assert all_matches["search_matches"][-1]["kind"] == "comment"
        assert (
            client.get("/v1/bootstrap", headers=headers).json()["items"][0]["search_matches"] == []
        )
    assert SettingsStore(paths).load().search_match_limit == 12


def test_nested_include_search_keeps_file_line_and_updates_after_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    source = _scenario(workspace, "included")
    source.write_text(source.read_text() + "includes: [fragments/hosts.yaml]\n")
    include = source.parent / "fragments/hosts.yaml"
    include.parent.mkdir()
    include.write_text("extra_hosts:\n  - hostname: unique-workstation\n")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    headers = {"X-EForge-Token": "secret"}
    with TestClient(create_app(_paths(tmp_path / "app"), "secret")) as client:
        matches = client.get("/v1/items?search=unique-workstation", headers=headers).json()
        assert len(matches) == 1
        match = matches[0]["search_matches"][0]
        assert match["file"] == "fragments/hosts.yaml"
        assert match["field"] == "extra_hosts[0].hostname"
        assert match["line"] == 2
        # Search uses the coherent index until the files are refreshed.
        include.write_text("extra_hosts:\n  - hostname: new-name\n")
        store = client.app.state.studio.store
        assert len(store.search_items(workspace, "unique-workstation")) == 1
        client.post("/v1/library/refresh", headers=headers)
        assert store.search_items(workspace, "unique-workstation") == []
        assert store.search_items(workspace, "new-name")


@pytest.mark.parametrize("limit", [0, -1, 51])
def test_invalid_excerpt_limits_are_rejected(limit: int) -> None:
    with pytest.raises(ValueError):
        StudioSettings(search_match_limit=limit)


def test_quoted_hash_is_a_value_and_inline_comments_remain_searchable() -> None:
    from evidenceforge.studio.search import matching_excerpts, yaml_entries

    entries = yaml_entries({"scenario.yaml": 'name: "#work" # work comment\nother: work\n'})
    matches, count = matching_excerpts(entries, [("", "work")], 5)
    assert count == 3
    assert [match.kind for match in matches] == ["value", "value", "comment"]
    assert matches[-1].excerpt == "work comment"

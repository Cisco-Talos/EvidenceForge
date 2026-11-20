# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Project default packs guide Studio authoring without changing scenario resolution."""

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from evidenceforge.studio.service import create_app, project_pack_instructions
from evidenceforge.studio.store import Project, ProjectDefaultPack
from tests.unit.test_studio_service import _paths

HEADERS = {"X-EForge-Token": "projects"}


def _released_industry(snapshot: dict[str, Any]) -> dict[str, str]:
    item = next(
        entry
        for entry in snapshot["items"]
        if entry["kind"] == "industry_pack" and entry["version"] and entry["publisher"]
    )
    return {
        "kind": "industry",
        "publisher": item["publisher"],
        "name": item["name"],
        "version": item["version"],
    }


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    with TestClient(create_app(_paths(tmp_path / "private"), "projects")) as test_client:
        yield test_client


def test_project_default_pack_is_saved_on_create_and_cleared_on_update(
    client: TestClient,
) -> None:
    pack = _released_industry(client.get("/v1/bootstrap", headers=HEADERS).json())

    created = client.post(
        "/v1/projects", headers=HEADERS, json={"name": "Finance", "default_pack": pack}
    )
    assert created.status_code == 200, created.text
    assert created.json()["default_pack"] == pack
    project_id = created.json()["id"]

    renamed = client.patch(f"/v1/projects/{project_id}", headers=HEADERS, json={"name": "Fin"})
    assert renamed.json()["default_pack"] == pack
    cleared = client.patch(
        f"/v1/projects/{project_id}", headers=HEADERS, json={"default_pack": None}
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["default_pack"] is None
    reloaded = client.get("/v1/bootstrap", headers=HEADERS).json()
    assert next(p for p in reloaded["projects"] if p["id"] == project_id)["default_pack"] is None


def test_project_default_pack_must_be_a_released_pack_in_the_workspace(
    client: TestClient,
) -> None:
    missing = {"kind": "organization", "publisher": "nobody", "name": "ghost", "version": "9.9.9"}

    response = client.post(
        "/v1/projects", headers=HEADERS, json={"name": "Ghost", "default_pack": missing}
    )

    assert response.status_code == 400
    assert "released organization pack" in response.json()["detail"]


def test_project_pack_instructions_only_guide_scenario_authoring(tmp_path: Path) -> None:
    project = Project(
        workspace=tmp_path,
        name="Acme",
        default_pack=ProjectDefaultPack(
            kind="organization", publisher="talos", name="acme", version="2.1.0"
        ),
    )

    text = project_pack_instructions(project, "scenario")

    assert "talos/acme version 2.1.0" in text
    assert "Never replace pack choices the scenario already declares" in text
    assert project_pack_instructions(project, "industry_pack") == ""
    assert (
        project_pack_instructions(project.model_copy(update={"default_pack": None}), "scenario")
        == ""
    )
    assert project_pack_instructions(None, "scenario") == ""

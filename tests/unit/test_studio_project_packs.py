# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Project default packs guide Studio authoring without changing scenario resolution."""

from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from evidenceforge.artifacts.lifecycle import create_draft, publish
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
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
    assert "authoring a new scenario without a pack choice" in text
    assert "unrelated edits and project moves, including authored inline environments" in text
    assert "An explicit user request authorizes changing or removing declared" in text
    assert project_pack_instructions(project, "industry_pack") == ""
    assert (
        project_pack_instructions(project.model_copy(update={"default_pack": None}), "scenario")
        == ""
    )
    assert project_pack_instructions(None, "scenario") == ""


TALUS = "package:evidenceforge:organization:talus-enterprises@1.0.0"
NORTHSTAR = "package:evidenceforge:organization:northstar-health@1.0.0"


def _packed_scenario(workspace: Path, reference: str) -> tuple[Path, Path]:
    pack, version = reference.split(":")[-1].split("@")
    source = workspace / "scenarios" / "pack-review" / "scenario.yaml"
    source.parent.mkdir(parents=True)
    declaration = source.parent / "composition.yaml"
    declaration.write_text(
        "# Keep the companion comment\n"
        "composition:\n"
        "  organization:\n"
        "    source: package\n"
        "    publisher: evidenceforge\n"
        f"    name: {pack}\n"
        f"    version: '{version}'\n"
        "\n# Keep the authored override\n"
        "environment:\n"
        "  description: Scenario-specific environment\n"
    )
    fixture = Path(__file__).parents[1] / "fixtures/scenarios/northstar-health-pack.yaml"
    data = yaml.safe_load(fixture.read_text())
    data.pop("composition")
    source.write_text("include: composition.yaml\n" + yaml.safe_dump(data, sort_keys=False))
    return source, declaration


def test_move_and_review_exact_project_pack_preserves_authored_sources(
    client: TestClient, tmp_path: Path
) -> None:
    workspace = tmp_path / "workspace"
    original, original_declaration = _packed_scenario(workspace, NORTHSTAR)
    source = create_draft(original, project_root=workspace)
    declaration = source.with_name(original_declaration.name)
    root_bytes = source.read_bytes()
    old_bytes = declaration.read_bytes()
    assert client.post("/v1/library/refresh", headers=HEADERS).status_code == 200
    snapshot = client.get("/v1/bootstrap", headers=HEADERS).json()
    item = next(entry for entry in snapshot["items"] if entry["path"] == str(source))
    project = client.post(
        "/v1/projects",
        headers=HEADERS,
        json={
            "name": "Talus",
            "default_pack": {
                "kind": "organization",
                "publisher": "evidenceforge",
                "name": "talus-enterprises",
                "version": "1.0.0",
            },
        },
    ).json()
    target = f"/v1/scenario-pack-targets/{item['id']}"
    assert client.get(f"{target}/project-default", headers=HEADERS).json() is None
    moved = client.patch(
        f"/v1/items/{item['id']}", headers=HEADERS, json={"project_id": project["id"]}
    )
    assert moved.status_code == 200, moved.text
    assert client.get(f"{target}/project-default", headers=HEADERS).json() == TALUS
    assert declaration.read_bytes() == old_bytes

    choice = {"references": [TALUS]}
    first = client.post(f"{target}/review", headers=HEADERS, json=choice)
    assert first.status_code == 200, first.text
    review = first.json()
    assert review["can_apply"], review
    assert review["current_references"] == [NORTHSTAR]
    assert {(pack["name"], pack["version"]) for pack in review["proposed_packs"]} == {
        ("technology", "1.0.0"),
        ("talus-enterprises", "1.0.0"),
    }
    assert "environment.description" in review["overrides"]
    assert any("atlas.mercer" in change for change in review["changes"])
    assert declaration.read_bytes() == old_bytes

    declaration.write_bytes(old_bytes + b"# Concurrent local change\n")
    stale = client.post(
        f"{target}/review", headers=HEADERS, json={**choice, "revision": review["revision"]}
    )
    assert stale.status_code == 409, stale.text
    assert b"northstar-health" in declaration.read_bytes()

    refreshed = client.post(f"{target}/review", headers=HEADERS, json=choice).json()
    applied = client.post(
        f"{target}/review", headers=HEADERS, json={**choice, "revision": refreshed["revision"]}
    )
    assert applied.status_code == 200, applied.text
    assert source.read_bytes() == root_bytes
    edited = declaration.read_bytes()
    for retained in (
        b"# Keep the companion comment",
        b"# Keep the authored override",
        b"description: Scenario-specific environment",
        b"# Concurrent local change",
    ):
        assert retained in edited
    assert b"name: talus-enterprises" in edited
    assert b"name: northstar-health" in original_declaration.read_bytes()
    assert client.get(f"{target}/project-default", headers=HEADERS).json() is None


def test_review_blocks_a_pack_swap_that_breaks_authored_references(tmp_path: Path) -> None:
    from evidenceforge.studio.scenario_packs import ScenarioPackEdit, change_scenario_packs

    source, declaration = _packed_scenario(tmp_path, TALUS)
    source.write_text(
        source.read_text() + "storyline:\n"
        "  - id: baseline-login\n"
        "    time: '+10m'\n"
        "    actor: atlas.mercer\n"
        "    system: ATLAS-WS01\n"
        "    activity: Local login\n"
        "    events: [{type: logon, logon_type: 2}]\n"
    )
    before = declaration.read_bytes()
    edit = ScenarioPackEdit(references=[NORTHSTAR])
    review = change_scenario_packs(source, tmp_path, edit)

    assert review.changed and not review.can_apply
    assert not review.current_error
    assert review.error_count
    assert any("storyline" in finding and "atlas.mercer" in finding for finding in review.findings)
    with pytest.raises(ValueError, match="Review a valid pack change"):
        change_scenario_packs(
            source, tmp_path, edit.model_copy(update={"revision": review.revision})
        )
    assert declaration.read_bytes() == before


def test_pack_changes_reject_published_scenarios_and_completed_drafts(tmp_path: Path) -> None:
    from evidenceforge.artifacts.lifecycle import ArtifactError
    from evidenceforge.studio.scenario_packs import ScenarioPackEdit, change_scenario_packs

    source, _ = _packed_scenario(tmp_path, NORTHSTAR)
    set_publisher(
        tmp_path,
        PublisherIdentity(publisher="pack-review", publisher_display_name="Pack Review"),
        scope="project",
        force=False,
    )
    draft = create_draft(source, project_root=tmp_path)
    release = publish(draft, project_root=tmp_path, accept_warnings=True)
    for protected, reason in ((release, "immutable"), (draft, "published")):
        before = protected.read_bytes()
        with pytest.raises(ArtifactError, match=reason):
            change_scenario_packs(protected, tmp_path, ScenarioPackEdit(references=[TALUS]))
        assert protected.read_bytes() == before

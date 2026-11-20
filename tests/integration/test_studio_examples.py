"""Fast installation, upgrade, removal and API contracts using real temporary state."""

import asyncio
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from evidenceforge.artifacts.lifecycle import inspect_artifact
from evidenceforge.artifacts.removal import remove_scenario, review_scenario_deletion
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.desktop.library import discover_scenarios
from evidenceforge.studio import examples as module
from evidenceforge.studio.examples import enroll_examples, install_examples, reconcile_examples
from evidenceforge.studio.service import StudioService, create_app
from evidenceforge.studio.state_database import DATABASE_VERSION, MIGRATIONS, migrate_database
from evidenceforge.studio.state_upgrade import StateCoordinator
from evidenceforge.studio.store import Project, StudioStore
from tests.support.examples import publish_example
from tests.support.studio_state import paths


@pytest.fixture(scope="module")
def releases(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("example-releases")
    for name, version in [
        ("example-one", "1.0.0"),
        ("example-one", "1.1.0"),
        ("example-two", "1.0.0"),
    ]:
        published = publish_example(root / f"author-{name}-{version}", name, version)
        shutil.copytree(published, root / "collection" / name / version)
    return root / "collection"


@pytest.fixture
def collection(tmp_path: Path, releases: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "examples"
    root.mkdir()
    monkeypatch.setenv(module.EXAMPLES_DIRECTORY_ENV, str(root))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "unused-home")
    return root


@pytest.fixture
def store(tmp_path: Path) -> Iterator[StudioStore]:
    value = StudioStore(tmp_path / "private/data/studio.sqlite")
    yield value
    value.close()


def index(store: StudioStore, workspace: Path) -> None:
    for source in discover_scenarios(workspace, []):
        store.upsert_item(workspace, "scenario", source)
    reconcile_examples(store, workspace)


def add(
    collection: Path, releases: Path, name: str = "example-one", version: str = "1.0.0"
) -> None:
    shutil.copytree(releases / name / version, collection / name / version)


def test_empty_first_run_restart_and_later_content(
    tmp_path: Path, store: StudioStore, collection: Path, releases: Path
) -> None:
    workspace = tmp_path / "workspace"
    enroll_examples(store, workspace)
    install_examples(store, workspace)
    project = store.projects(workspace)[0]
    assert project.name == "Example Scenarios"
    enroll_examples(store, workspace)
    install_examples(store, workspace)
    assert store.projects(workspace) == [project]
    add(collection, releases)
    install_examples(store, workspace)
    index(store, workspace)
    assert len(store.items(workspace, "scenario")) == 1
    assert store.items(workspace, "scenario")[0].project_id == project.id
    assert module.examples_status(store, workspace).automatic_updates


def test_custom_workspace_remains_manual_and_collision_does_not_adopt_project(
    tmp_path: Path, store: StudioStore, collection: Path, releases: Path
) -> None:
    workspace = tmp_path / "custom"
    unrelated = Project(workspace=workspace, name="Example Scenarios")
    store.save_project(unrelated)
    add(collection, releases)
    install_examples(store, workspace)
    assert store.example_installation(workspace) is None
    install_examples(store, workspace, manual=True)
    index(store, workspace)
    state = store.example_installation(workspace)
    assert state and not state.automatic and state.project_id != unrelated.id
    assert store.project(state.project_id).name == "Example Scenarios (2)"
    add(collection, releases, version="1.1.0")
    install_examples(store, workspace)
    index(store, workspace)
    assert len(store.items(workspace, "scenario")) == 1
    install_examples(store, workspace, manual=True)
    index(store, workspace)
    assert len(store.items(workspace, "scenario")) == 2


def test_additive_upgrade_preserves_work_and_follows_project_moves(
    tmp_path: Path, store: StudioStore, collection: Path, releases: Path
) -> None:
    workspace = tmp_path / "workspace"
    enroll_examples(store, workspace)
    add(collection, releases)
    install_examples(store, workspace)
    index(store, workspace)
    original = store.items(workspace, "scenario")[0]
    before = original.path.read_bytes()
    user_project = Project(workspace=workspace, name="My exercises")
    store.save_project(user_project)
    original.project_id = user_project.id
    store.save_item(original)
    keep = workspace / "runs/keep.txt"
    keep.parent.mkdir()
    keep.write_text("existing output", encoding="utf-8")
    add(collection, releases, version="1.1.0")
    add(collection, releases, name="example-two")
    install_examples(store, workspace)
    index(store, workspace)
    items = store.items(workspace, "scenario")
    assert len(items) == 3
    assert all(item.project_id == user_project.id for item in items if item.name == "example-one")
    assert original.path.read_bytes() == before and keep.read_text() == "existing output"


def test_project_rename_delete_and_manual_restore(
    tmp_path: Path, store: StudioStore, collection: Path, releases: Path
) -> None:
    workspace = tmp_path / "workspace"
    enroll_examples(store, workspace)
    add(collection, releases)
    install_examples(store, workspace)
    index(store, workspace)
    project = store.projects(workspace)[0]
    project.name = "Renamed examples"
    store.save_project(project)
    add(collection, releases, version="1.1.0")
    install_examples(store, workspace)
    index(store, workspace)
    assert len(store.items(workspace, "scenario")) == 2
    store.delete_project(project)
    add(collection, releases, name="example-two")
    install_examples(store, workspace)
    index(store, workspace)
    assert not store.projects(workspace)
    assert len(store.items(workspace, "scenario")) == 2
    install_examples(store, workspace, manual=True)
    index(store, workspace)
    assert len(store.items(workspace, "scenario")) == 3
    assert all(item.project_id == project.id for item in store.items(workspace, "scenario"))


def test_individual_deletion_excludes_future_versions_until_manual_restore(
    tmp_path: Path, store: StudioStore, collection: Path, releases: Path
) -> None:
    workspace = tmp_path / "workspace"
    enroll_examples(store, workspace)
    add(collection, releases)
    install_examples(store, workspace)
    index(store, workspace)
    item = store.items(workspace, "scenario")[0]
    review = review_scenario_deletion(item.path, workspace)
    remove_scenario(item.path, workspace, review.revision)
    store.remove_scenario(item.id)
    add(collection, releases, version="1.1.0")
    install_examples(store, workspace)
    index(store, workspace)
    assert store.items(workspace, "scenario") == []
    assert store.example_installation(workspace).excluded == {"evidenceforge/example-one"}
    install_examples(store, workspace, manual=True)
    index(store, workspace)
    assert len(store.items(workspace, "scenario")) == 2
    assert not store.example_installation(workspace).excluded


@pytest.mark.parametrize("boundary", ["after_files", "before_index"])
def test_interrupted_install_retries_without_duplicates(
    tmp_path: Path,
    store: StudioStore,
    collection: Path,
    releases: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    workspace = tmp_path / "workspace"
    enroll_examples(store, workspace)
    add(collection, releases)
    original_import = module.import_release

    def interrupted(*args: object, **kwargs: object) -> Path:
        original_import(*args, **kwargs)
        raise OSError("interrupted after file commit")

    if boundary == "after_files":
        monkeypatch.setattr(module, "import_release", interrupted)
    install_examples(store, workspace)
    if boundary == "after_files":
        assert store.example_installation(workspace).error
        # A real failed startup still scans files already committed before the failure.
        index(store, workspace)
        assert store.items(workspace, "scenario")[0].project_id == store.projects(workspace)[0].id
    # Reopen the database as after a real service restart, without changing the workspace.
    reopened = StudioStore(store.path)
    try:
        monkeypatch.setattr(module, "import_release", original_import)
        install_examples(reopened, workspace)
        index(reopened, workspace)
        assert len(reopened.projects(workspace)) == 1
        assert len(reopened.items(workspace, "scenario")) == 1
        assert not reopened.example_installation(workspace).error
    finally:
        reopened.close()


def test_tampering_does_not_overwrite_installed_files(
    tmp_path: Path, store: StudioStore, collection: Path, releases: Path
) -> None:
    workspace = tmp_path / "workspace"
    enroll_examples(store, workspace)
    add(collection, releases)
    install_examples(store, workspace)
    index(store, workspace)
    item = store.items(workspace, "scenario")[0]
    item.path.write_text("user modification", encoding="utf-8")
    install_examples(store, workspace, manual=True)
    assert "modified" in store.example_installation(workspace).error
    assert item.path.read_text() == "user modification"


def test_conflicting_preexisting_release_keeps_user_project_and_identity(
    tmp_path: Path, store: StudioStore, collection: Path, releases: Path
) -> None:
    from evidenceforge.artifacts.portable import import_release

    workspace = tmp_path / "workspace"
    conflicting = publish_example(tmp_path / "different-author")
    source = import_release(conflicting, project_root=workspace)
    index(store, workspace)
    item = store.items(workspace, "scenario")[0]
    project = Project(workspace=workspace, name="My project")
    store.save_project(project)
    item.project_id = project.id
    store.save_item(item)
    enroll_examples(store, workspace)
    add(collection, releases)
    install_examples(store, workspace)
    index(store, workspace)
    assert store.example_installation(workspace).error
    assert store.item(item.id).project_id == project.id
    assert not module.is_example(store, workspace, source)


def test_manual_restoration_resumes_after_file_commit_before_index_intent(
    tmp_path: Path,
    store: StudioStore,
    collection: Path,
    releases: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    enroll_examples(store, workspace)
    add(collection, releases)
    install_examples(store, workspace)
    index(store, workspace)
    item = store.items(workspace, "scenario")[0]
    project_id = item.project_id
    review = review_scenario_deletion(item.path, workspace)
    remove_scenario(item.path, workspace, review.revision)
    store.remove_scenario(item.id)
    original_import = module.import_release

    def interrupted(
        path: Path,
        *,
        project_root: Path,
        restore_deleted: bool = False,
        allow_hardlinks: bool = False,
    ) -> Path:
        original_import(
            path,
            project_root=project_root,
            restore_deleted=restore_deleted,
            allow_hardlinks=allow_hardlinks,
        )
        raise OSError("Interrupted restoration after file commit")

    monkeypatch.setattr(module, "import_release", interrupted)
    install_examples(store, workspace, manual=True)
    assert store.example_installation(workspace).manual_pending
    monkeypatch.setattr(module, "import_release", original_import)
    install_examples(store, workspace)
    index(store, workspace)
    assert store.items(workspace, "scenario")[0].project_id == project_id
    assert not store.example_installation(workspace).manual_pending


def test_workspace_switching_updates_only_original_enrolled_workspace(
    tmp_path: Path, collection: Path, releases: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    default = tmp_path / "default"
    custom = tmp_path / "custom"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(default))
    add(collection, releases)
    headers = {"X-EForge-Token": "examples"}
    app = create_app(paths(tmp_path / "private"), "examples")
    with TestClient(app) as client:
        assert (
            client.post(
                "/v1/workspaces/select", headers=headers, json={"path": str(custom)}
            ).status_code
            == 200
        )
        assert not app.state.studio.store.projects(custom)
        result = client.post(
            "/v1/examples/install", headers=headers, json={"workspace": str(custom)}
        )
        assert result.status_code == 200 and not result.json()["automatic_updates"]
        add(collection, releases, name="example-two")
        assert (
            client.post(
                "/v1/workspaces/select", headers=headers, json={"path": str(default)}
            ).status_code
            == 200
        )
        assert len(app.state.studio.store.items(default, "scenario")) == 2
        assert (
            client.post(
                "/v1/workspaces/select", headers=headers, json={"path": str(custom)}
            ).status_code
            == 200
        )
        assert len(app.state.studio.store.items(custom, "scenario")) == 1


def test_first_run_enrollment_and_existing_user_upgrade_are_distinct(
    tmp_path: Path, collection: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    private = paths(tmp_path / "first-user")
    service = StudioService(private, "examples")
    assert service.store.example_installation(workspace).automatic
    asyncio.run(service.scan(update_examples=True))
    asyncio.run(service.stop())
    # Another OS account sharing an installation gets independent first-run enrollment.
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "other-workspace"))
    other = StudioService(paths(tmp_path / "other-user"), "examples")
    assert other.store.example_installation(other.settings.workspace).automatic
    asyncio.run(other.stop())
    # Existing version-3 state upgrades without acquiring first-run eligibility.
    old = paths(tmp_path / "existing-user")
    old.data.mkdir(parents=True)
    migrate_database(old.database_file, "test", migrations=MIGRATIONS[:3])
    coordinator = StateCoordinator(old)
    coordinator.prepare()
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    existing = StudioService(old, "examples", coordinator=coordinator)
    assert existing.store.example_installation(existing.settings.workspace) is None
    assert DATABASE_VERSION >= 4
    asyncio.run(existing.stop())


@pytest.mark.parametrize("publisher", [None, "my-team"])
def test_api_installs_and_forks_with_ordinary_publisher_and_destination_choices(
    tmp_path: Path,
    collection: Path,
    releases: Path,
    monkeypatch: pytest.MonkeyPatch,
    publisher: str | None,
) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    add(collection, releases)
    if publisher:
        set_publisher(
            workspace,
            PublisherIdentity(publisher=publisher, publisher_display_name="Me"),
            scope="project",
            force=True,
        )
    headers = {"X-EForge-Token": "examples"}
    app = create_app(paths(tmp_path / "private"), "examples")
    with TestClient(app) as client:
        assert client.get("/v1/examples").status_code == 401
        snapshot = client.get("/v1/bootstrap", headers=headers).json()
        item = next(item for item in snapshot["items"] if item["kind"] == "scenario")
        assert item["id"] in snapshot["example_sources"]
        endpoint = f"/v1/items/{item['id']}/lifecycle"
        info = client.get(endpoint, headers=headers).json()
        assert info["example_source"]
        if publisher:
            project = client.post(
                "/v1/projects", headers=headers, json={"name": "My project"}
            ).json()
            project_id = project["id"]
        else:
            project_id = None
        result = client.post(
            endpoint,
            headers=headers,
            json={"action": "draft", "project_id": project_id, "expected_digest": info["digest"]},
        )
        assert result.status_code == 200, result.text
        draft = Path(result.json()["path"])
        assert inspect_artifact(draft)["lifecycle"].get("publisher") == publisher
        assert app.state.studio.store.item(item["id"]).path == Path(item["path"])
        created = next(
            entry for entry in app.state.studio.store.items(workspace) if entry.path == draft
        )
        assert created.project_id == project_id
        cloned = client.post(
            f"/v1/scenarios/{item['id']}/clone",
            headers=headers,
            json={"name": "my-example-copy", "project_id": project_id},
        )
        assert cloned.status_code == 200, cloned.text
        assert cloned.json()["project_id"] == project_id
        assert (
            inspect_artifact(Path(cloned.json()["path"]))["lifecycle"].get("publisher") == publisher
        )
        response = client.post(
            "/v1/examples/install", headers=headers, json={"workspace": str(workspace)}
        )
        assert response.status_code == 200 and not response.json()["error"]
        assert (
            client.post(
                "/v1/examples/install",
                headers=headers,
                json={"workspace": str(tmp_path / "another")},
            ).status_code
            == 409
        )

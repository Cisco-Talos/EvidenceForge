"""Workspace-local example enrollment and retryable installation over shared file services."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from evidenceforge.artifacts.lifecycle import ArtifactError, inspect_artifact
from evidenceforge.artifacts.portable import import_release, release_destination
from evidenceforge.examples import collection_digest, discover_examples, examples_directory
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.studio.state_records_v4 import ExampleInstallation, InstalledExample
from evidenceforge.studio.store import Project, StudioStore

logger = logging.getLogger(__name__)

EXAMPLES_DIRECTORY_ENV = "EFORGE_STUDIO_EXAMPLES_DIR"
"""Developer and test override for the bundled collection Studio installs from."""


def _collection_root() -> Path:
    """Return the overridden collection, else the distribution's bundled examples."""
    override = os.environ.get(EXAMPLES_DIRECTORY_ENV)
    return Path(override).resolve() if override else examples_directory()


class ExamplesStatus(BaseModel):
    """Settings presentation for the current workspace and bundled collection."""

    model_config = ConfigDict(extra="forbid")

    directory: Path
    bundled_releases: int = 0
    automatic_updates: bool = False
    project_id: str | None = None
    error: str = ""


class ExamplesInstallRequest(BaseModel):
    """Bind a Settings action to the workspace the user was viewing."""

    model_config = ConfigDict(extra="forbid")

    workspace: Path


def enroll_examples(store: StudioStore, workspace: Path) -> None:
    """Persist first-run eligibility before initialization is marked complete."""
    if store.example_installation(workspace) is None:
        store.save_example_installation(
            ExampleInstallation(
                workspace=workspace.resolve(), automatic=True, project_id=uuid4().hex
            )
        )


def _project_exists(store: StudioStore, state: ExampleInstallation) -> bool:
    project = store.project(state.project_id)
    return project is not None and project.workspace.resolve() == state.workspace.resolve()


def _ensure_project(store: StudioStore, state: ExampleInstallation) -> None:
    if _project_exists(store, state):
        return
    names = {project.name.casefold() for project in store.projects(state.workspace)}
    name = "Example Scenarios"
    suffix = 2
    while name.casefold() in names:
        name = f"Example Scenarios ({suffix})"
        suffix += 1
    store.save_project(Project(id=state.project_id, workspace=state.workspace, name=name))


def reconcile_examples(store: StudioStore, workspace: Path) -> None:
    """Complete retained index intents and remember removals without recreating files."""
    state = store.example_installation(workspace)
    if state is None:
        return
    before = state.model_dump_json()
    by_path = {item.path: item for item in store.items(workspace, "scenario")}
    for record in state.installed.values():
        if not record.path.is_file():
            if record.indexed:
                state.excluded.add(record.family)
            continue
        item = by_path.get(record.path)
        if not record.indexed and item is not None:
            try:
                if inspect_artifact(record.path)["digest"] != record.digest:
                    continue
            except (OSError, ValueError, EvidenceForgeError):
                continue
            project = store.project(record.project_id) if record.project_id else None
            item.project_id = project.id if project and project.workspace == workspace else None
            store.save_item(item)
            record.indexed = True
    if state.model_dump_json() != before:
        store.save_example_installation(state)


def install_examples(store: StudioStore, workspace: Path, *, manual: bool = False) -> None:
    """Install additive exact releases; explicit installation also restores removals."""
    workspace = workspace.resolve()
    state = store.example_installation(workspace)
    if state is None:
        if not manual:
            return
        state = ExampleInstallation(workspace=workspace, project_id=uuid4().hex)
        store.save_example_installation(state)
    manual_operation = manual or state.manual_pending
    if not manual and (
        not state.automatic or state.project_created and not _project_exists(store, state)
    ):
        return
    try:
        reconcile_examples(store, workspace)
        state = store.example_installation(workspace) or state
        state.manual_pending = manual_operation
        state.regroup_pending = state.regroup_pending or (
            manual_operation and state.project_created and not _project_exists(store, state)
        )
        store.save_example_installation(state)
        _ensure_project(store, state)
        state.project_created = True
        if manual_operation:
            state.excluded.clear()
        state.error = ""
        # The stable ID and enrollment must survive an interrupted empty/partial install.
        store.save_example_installation(state)
        examples = discover_examples(_collection_root())
        existing = {item.path: item for item in store.items(workspace, "scenario")}
        for example in examples:
            if example.family in state.excluded:
                continue
            previous = state.installed.get(example.identity)
            if previous and previous.digest != example.receipt.digest:
                raise ArtifactError("Bundled example changed under an existing release identity")
            family_items = [
                existing[record.path]
                for record in state.installed.values()
                if record.family == example.family and record.path in existing
            ]
            # Follow the most recent existing family member, including a deliberate move.
            family_items.sort(key=lambda item: tuple(int(part) for part in item.version.split(".")))
            project_id = family_items[-1].project_id if family_items else state.project_id
            if state.regroup_pending and project_id is None:
                project_id = state.project_id
            was_missing = previous is not None and not previous.path.is_file()
            path = (
                release_destination(example.receipt, project_root=workspace)
                / example.receipt.entrypoint
            )
            if previous is None:
                if path in existing:
                    project_id = existing[path].project_id
                state.installed[example.identity] = InstalledExample(
                    family=example.family,
                    path=path,
                    digest=example.receipt.digest,
                    project_id=project_id,
                )
                store.save_example_installation(state)
            if previous is not None and (was_missing or state.regroup_pending):
                previous.indexed = False
                previous.project_id = project_id
                store.save_example_installation(state)
            import_release(
                example.root,
                project_root=workspace,
                restore_deleted=manual_operation,
                allow_hardlinks=True,
            )
            store.save_example_installation(state)
        state.collection_digest = collection_digest(examples)
        state.manual_pending = False
        state.regroup_pending = False
        store.save_example_installation(state)
    except (OSError, ValueError, EvidenceForgeError) as exc:
        state.error = str(exc)
        store.save_example_installation(state)
        logger.warning("Example installation failed: %s", exc)


def examples_status(store: StudioStore, workspace: Path) -> ExamplesStatus:
    """Describe failures without preventing normal Studio use."""
    state = store.example_installation(workspace)
    try:
        root = _collection_root()
        count = len(discover_examples(root))
        error = state.error if state else ""
    except (OSError, ValueError, EvidenceForgeError) as exc:
        root = Path(__file__).resolve().parents[1] / "_data" / "examples"
        count, error = 0, str(exc)
    return ExamplesStatus(
        directory=root,
        bundled_releases=count,
        automatic_updates=bool(state and state.automatic and _project_exists(store, state)),
        project_id=state.project_id if state and _project_exists(store, state) else None,
        error=error,
    )


def is_example(store: StudioStore, workspace: Path, source: Path) -> bool:
    """Recognize an installed official source independently of project placement."""
    state = store.example_installation(workspace)
    return bool(
        state
        and any(record.indexed and record.path == source for record in state.installed.values())
    )

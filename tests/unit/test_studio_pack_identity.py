"""Bundled catalog identity survives runtime relocation and repairs historical aliases."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Literal

import pytest

from evidenceforge.desktop.library import LibraryItem
from evidenceforge.studio.store import Conversation, StudioStore

PackKind = Literal["industry_pack", "organization_pack"]


def _source(
    root: Path,
    kind: PackKind,
    *,
    publisher: str = "evidenceforge",
    version: str = "1.0.0",
    scope: str = "bundled",
) -> LibraryItem:
    path = root / publisher / kind / "office" / version / "pack.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    text = f"name: office\npublisher: {publisher}\nversion: {version}\ndescription: Office pack\n"
    path.write_text(text)
    return LibraryItem(
        path=path,
        name="office",
        kind=kind.removesuffix("_pack"),
        publisher=publisher,
        version=version,
        pack_source=scope,
        description="Office pack",
        search_text=text,
    )


def _historical_item(
    store: StudioStore, workspace: Path, kind: PackKind, source: LibraryItem
) -> str:
    # Reconstruct the old path-keyed behavior without depending on the fixed upsert.
    item = store.upsert_item(workspace, kind, source.model_copy(update={"pack_source": ""}))
    item.pack_source = "bundled"
    store.save_item(item)
    return item.id


@pytest.mark.parametrize("kind", ["industry_pack", "organization_pack"])
def test_bundled_identity_survives_repeated_runtime_relocations(
    tmp_path: Path, kind: PackKind
) -> None:
    workspace = tmp_path / "workspace"
    store = StudioStore(tmp_path / "private/studio.sqlite")
    try:
        first = store.upsert_item(workspace, kind, _source(tmp_path / "source-checkout", kind))
        first.project_id = "training-project"
        first.folder = "Exercises"
        first.hidden = True
        store.save_item(first)
        for release in ("runtime-a", "runtime-b", "runtime-c", "source-checkout"):
            source = _source(tmp_path / release, kind)
            item = store.upsert_item(workspace, kind, source)
            assert item.id == first.id
            assert item.path == source.path
            assert item.project_id == first.project_id
            assert item.folder == first.folder
            assert item.hidden
            assert len(store.items(workspace, kind)) == 1
            assert store.upsert_item(workspace, kind, source).id == first.id
        assert [item.id for item in store.search_items(workspace, "office")] == [first.id]
    finally:
        store.close()


@pytest.mark.parametrize("kind", ["industry_pack", "organization_pack"])
def test_historical_aliases_merge_chats_and_organization_without_touching_files(
    tmp_path: Path, kind: PackKind
) -> None:
    workspace = tmp_path / "workspace"
    database = tmp_path / "private/studio.sqlite"
    store = StudioStore(database)
    try:
        sources = [_source(tmp_path / runtime, kind) for runtime in ("checkout", "old", "new")]
        identities = [_historical_item(store, workspace, kind, source) for source in sources]
        alias = store.item(identities[1])
        assert alias is not None
        alias.project_id = "assigned-project"
        alias.folder = "My packs"
        alias.hidden = True
        store.save_item(alias)
        chats = [
            Conversation(
                workspace=workspace,
                item_id=identity,
                thread_id=f"codex-{index}",
                title=f"Pack chat {index}",
                active=index == 1,
            )
            for index, identity in enumerate(identities)
        ]
        for chat in chats:
            store.save_conversation(chat)
        before = {source.path: source.path.read_bytes() for source in sources}
        # Also cover the early-return case where the selected runtime is the oldest path.
        canonical = store.upsert_item(workspace, kind, sources[0])
        assert canonical.id == identities[0]
        assert canonical.project_id == alias.project_id
        assert canonical.folder == alias.folder
        assert canonical.hidden
        saved = store.item(canonical.id)
        assert saved == canonical
        assert [item.id for item in store.items(workspace)] == [canonical.id]
        assert all(store.item(identity) is None for identity in identities[1:])
        recovered = store.conversations(workspace, canonical.id)
        assert {chat.id for chat in recovered} == {chat.id for chat in chats}
        assert {chat.thread_id for chat in recovered} == {chat.thread_id for chat in chats}
        assert sum(chat.active for chat in recovered) == 1
        assert {chat.updated_at for chat in recovered} == {chat.updated_at for chat in chats}
        assert [item.id for item in store.search_items(workspace, "office")] == [canonical.id]
        assert before == {source.path: source.path.read_bytes() for source in sources}
    finally:
        store.close()
    reopened = StudioStore(database)
    try:
        assert reopened.item(identities[0]) == canonical
        assert len(reopened.conversations(workspace, identities[0])) == 3
    finally:
        reopened.close()


def test_logical_identity_keeps_versions_publishers_scopes_and_workspaces_distinct(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    other_workspace = tmp_path / "other-workspace"
    store = StudioStore(tmp_path / "private/studio.sqlite")
    try:
        identities = [
            store.upsert_item(workspace, kind, source).id
            for kind, source in (
                ("industry_pack", _source(tmp_path / "bundle", "industry_pack")),
                ("organization_pack", _source(tmp_path / "bundle", "organization_pack")),
                (
                    "industry_pack",
                    _source(tmp_path / "bundle", "industry_pack", version="1.1.0"),
                ),
                (
                    "industry_pack",
                    _source(tmp_path / "bundle", "industry_pack", publisher="other"),
                ),
                (
                    "industry_pack",
                    _source(tmp_path / "project-a", "industry_pack", scope="workspace"),
                ),
                (
                    "industry_pack",
                    _source(tmp_path / "project-b", "industry_pack", scope="workspace"),
                ),
            )
        ]
        other = store.upsert_item(
            other_workspace, "industry_pack", _source(tmp_path / "bundle", "industry_pack")
        )
        assert len(set(identities + [other.id])) == 7
        assert len(store.items(workspace)) == 6
        assert len(store.items(other_workspace)) == 1
    finally:
        store.close()


def test_failed_relocation_rolls_back_alias_removal_and_chat_reassignment(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    database = tmp_path / "private/studio.sqlite"
    store = StudioStore(database)
    try:
        sources = [_source(tmp_path / runtime, "industry_pack") for runtime in ("old", "new")]
        identities = [
            _historical_item(store, workspace, "industry_pack", source) for source in sources
        ]
        chat = Conversation(workspace=workspace, item_id=identities[1], thread_id="retain-thread")
        store.save_conversation(chat)
        before = store.items(workspace)
        with sqlite3.connect(database) as connection:
            connection.execute(
                "CREATE TRIGGER refuse_relocation BEFORE UPDATE ON items "
                "BEGIN SELECT RAISE(ABORT, 'forced relocation failure'); END"
            )
        with pytest.raises(sqlite3.IntegrityError, match="forced relocation failure"):
            store.upsert_item(workspace, "industry_pack", sources[1])
        assert store.items(workspace) == before
        assert store.conversation(chat.id) == chat
        assert len(store.search_items(workspace, "office")) == 2
    finally:
        store.close()

"""Uninstall category isolation, inventory authority, ownership and active-writer refusal."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

import pytest

from evidenceforge.cli.install_skills import install_chatgpt_skills, install_skills
from evidenceforge.studio.state_io import StateLock, StudioStateError, private_directory
from evidenceforge.studio.windows_uninstall import (
    Category,
    CleanupPlan,
    UserLocations,
    build_plan,
    describe,
    execute,
)


@pytest.fixture
def locations(tmp_path: Path) -> UserLocations:
    profile = tmp_path / "user ü 汉"
    private_directory(profile)
    account = "test-user"
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import current_user_sid

        account = current_user_sid()
    return UserLocations(
        profile=profile,
        local=profile / "AppData/Local",
        documents=profile / "Documents",
        account=account,
    )


def write(path: Path, text: str = "preserve") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_default_is_read_only_and_preserves_every_category(locations: UserLocations) -> None:
    state = write(locations.private / "settings-secret.txt")
    work = write(locations.documents / "EvidenceForge/.eforge/artifacts/draft/source.yaml")
    publisher = write(
        locations.profile / ".eforge/publisher.yaml",
        "publisher: test\npublisher_display_name: Test\n",
    )
    before = {path: path.read_bytes() for path in (state, work, publisher)}
    plan = build_plan(locations)
    execute(plan, set())
    assert {path: path.read_bytes() for path in before} == before
    assert "preserved (the default)" in describe(plan, set())
    assert not list(locations.profile.rglob("*.lock"))


@pytest.mark.parametrize(
    "selected", [{"private"}, {"skills"}, {"work"}, {"private", "skills", "work"}]
)
def test_selected_categories_are_independent_and_other_accounts_stay(
    locations: UserLocations, selected: set[str]
) -> None:
    state = write(locations.private / "runtimes/retained/python.exe")
    webview = write(locations.local / "org.evidenceforge.studio/cookies")
    work = write(
        locations.documents / "EvidenceForge/.eforge/artifacts/drafts/scenario/source.yaml"
    )
    publisher = write(
        locations.profile / ".eforge/publisher.yaml",
        "publisher: test\npublisher_display_name: Test\n",
    )
    other_account = write(locations.profile.parent / "other-user/private/secret")
    unrelated = write(locations.documents / "EvidenceForge/unrelated.txt")
    plan = build_plan(locations)
    execute(plan, selected)
    assert state.exists() is ("private" not in selected)
    assert webview.exists() is ("private" not in selected)
    assert work.exists() is ("work" not in selected)
    assert publisher.exists() is ("skills" not in selected)
    assert other_account.read_text() == "preserve"
    assert unrelated.read_text() == "preserve"
    assert not list(locations.profile.rglob(".eforge-uninstall-*"))


def test_clean_uninstall_finds_local_default_even_after_private_settings_are_removed(
    locations: UserLocations,
) -> None:
    local = locations.profile / "EvidenceForge"
    work = write(local / ".eforge/artifacts/drafts/scenario/source.yaml")
    unrelated = write(local / "my-notes.txt")
    legacy = write(locations.documents / "EvidenceForge/.eforge/artifacts/legacy/source.yaml")
    plan = build_plan(locations)
    execute(plan, {"work"})
    assert not work.exists() and not legacy.exists()
    assert unrelated.read_text() == "preserve"


def test_modified_known_skills_are_explicit_and_unrelated_files_survive(
    locations: UserLocations,
) -> None:
    skills = locations.profile / ".agents/skills"
    install_chatgpt_skills(skills)
    claude = locations.profile / ".claude/commands"
    install_skills(claude)
    known = skills / "eforge-generate/references/project-context.md"
    known.write_text("my customized EvidenceForge instructions", encoding="utf-8")
    added = write(skills / "eforge-generate/my-notes.txt")
    unrelated = write(skills / "another-tool/SKILL.md")
    cli_settings = write(locations.profile / ".codex/config.toml")
    plan = build_plan(locations)
    review = describe(plan, {"skills"})
    assert str(known) in review and "local edits" in review
    execute(plan, {"skills"})
    assert not known.exists()
    assert not (skills / "eforge-generate/SKILL.md").exists()
    assert not (claude / "eforge/generate.md").exists()
    assert added.exists() and unrelated.exists() and cli_settings.exists()


def test_inventory_change_aborts_before_any_deletion(locations: UserLocations) -> None:
    first = write(locations.private / "first")
    changed = write(locations.local / "org.evidenceforge.studio/changed")
    plan = build_plan(locations)
    changed.write_text("changed after review")
    with pytest.raises(StudioStateError, match="changed after review"):
        execute(plan, {"private"})
    assert first.exists() and changed.exists()


def test_live_helper_lock_refuses_all_cleanup(locations: UserLocations) -> None:
    state = write(locations.private / "data")
    plan = build_plan(locations)
    with StateLock(locations.private / "service-instance.lock"):
        with pytest.raises(StudioStateError, match="Another Studio process"):
            execute(plan, {"private"})
    assert state.exists()


def test_retained_worker_refusal_precedes_staging(locations: UserLocations) -> None:
    state = write(locations.private / "data")
    plan = build_plan(locations)
    with patch(
        "evidenceforge.studio.state_upgrade.check_workers",
        side_effect=StudioStateError("worker active"),
    ):
        with pytest.raises(StudioStateError, match="worker active"):
            execute(plan, {"private"})
    assert state.exists()
    assert not list(locations.profile.rglob(".eforge-uninstall-*"))


def test_late_staging_failure_restores_all_already_staged_names(locations: UserLocations) -> None:
    from evidenceforge.studio import windows_uninstall as cleanup

    first = write(locations.private / "first")
    second = write(locations.local / "org.evidenceforge.studio/second")
    plan = build_plan(locations)
    move = cleanup._move
    count = 0

    def fail_second(source: Path, target: Path, *, directory: bool) -> None:
        nonlocal count
        count += 1
        if count == 2:
            raise PermissionError("simulated locked data")
        move(source, target, directory=directory)

    with patch.object(cleanup, "_move", side_effect=fail_second):
        with pytest.raises(PermissionError, match="locked data"):
            execute(plan, {"private"})
    assert first.exists() and second.exists()


def test_linked_private_root_is_never_followed(locations: UserLocations) -> None:
    external = write(locations.profile.parent / "unrelated/secret")
    locations.local.mkdir(parents=True)
    try:
        locations.private.symlink_to(external.parent, target_is_directory=True)
    except OSError as error:
        if os.name == "nt" and getattr(error, "winerror", None) == 1314:
            # The native junction test covers Windows hosts without symlink privilege.
            import subprocess

            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(locations.private), str(external.parent)],
                check=True,
                capture_output=True,
            )
        else:
            raise
    with pytest.raises(StudioStateError, match="link or reparse"):
        build_plan(locations)
    assert external.exists()


def test_workspace_and_external_exports_are_not_recursively_deleted(
    locations: UserLocations,
) -> None:
    outside = write(locations.profile.parent / "external/RESOLVED_SCENARIO.yaml")
    write(
        locations.private / "settings.json",
        json.dumps({"schema_version": 4, "settings": {"workspace": str(outside.parent)}}),
    )
    plan = build_plan(locations)
    assert str(outside.parent) in describe(plan, {"work"})
    execute(plan, {"work"})
    assert outside.exists()


def test_native_template_orders_maintenance_before_scope_and_preserves_silent_upgrade() -> None:
    template = (
        Path(__file__).resolve().parents[2] / "desktop-ui/packaging/windows-installer.nsi"
    ).read_text()
    assert template.index("Page custom PageReinstall") < template.index(
        "!insertmacro MULTIUSER_PAGE_INSTALLMODE"
    )
    assert "MUI_PAGE_CUSTOMFUNCTION_LEAVE un.ReviewCleanup" in template
    review = template[
        template.index("Function un.ReviewCleanup") : template.index(
            "FunctionEnd", template.index("Function un.ReviewCleanup")
        )
    ]
    cleanup = review.index("windows_uninstall --broker")
    assert review.index("CheckIfAppIsRunning") < cleanup
    assert "${IfNot} ${Silent}" in review[:cleanup]
    assert "$PassiveMode <> 1" in review[:cleanup] and "$UpdateMode <> 1" in review[:cleanup]
    assert "windows_uninstall --broker" not in template[template.index("Section Uninstall") :]


def test_nested_complete_and_incomplete_runs_are_selected_but_external_writer_blocks(
    locations: UserLocations,
) -> None:
    import socket

    complete = locations.documents / "EvidenceForge/runs/scenario/complete"
    incomplete = locations.documents / "EvidenceForge/runs/scenario/incomplete"
    final = write(complete / "RESOLVED_SCENARIO.yaml")
    lock = write(
        incomplete / ".eforge-generation/run.lock",
        json.dumps({"hostname": socket.gethostname(), "pid": os.getpid()}),
    )
    plan = build_plan(locations)
    assert {target.path for target in plan.targets if target.category == "work"} == {
        complete,
        incomplete,
    }
    from evidenceforge.generation.checkpoints.errors import CheckpointLockError

    with pytest.raises(CheckpointLockError, match="live process"):
        execute(plan, {"work"})
    assert final.exists() and lock.exists()
    lock.unlink()
    execute(build_plan(locations), {"work"})
    assert not complete.exists() and not incomplete.exists()


def test_directory_root_identity_is_independent_of_child_sort_order(
    locations: UserLocations,
) -> None:
    write(locations.private / " leading-space-file")
    plan = build_plan(locations)
    assert plan.targets[0].directory
    execute(plan, {"private"})
    assert not locations.private.exists()


def test_ordinary_lock_named_data_and_directories_are_included(locations: UserLocations) -> None:
    ordinary = write(locations.private / "cache/run.lock")
    nested = write(locations.private / "cache/install.lock/notes.txt")
    plan = build_plan(locations)
    selected_files = {entry.relative for target in plan.targets for entry in target.entries}
    assert "cache/run.lock" in selected_files
    assert "cache/install.lock" in selected_files
    execute(plan, {"private"})
    assert not ordinary.exists() and not nested.exists() and not locations.private.exists()


def test_populated_studio_database_cleanup_and_fresh_initialization(
    locations: UserLocations,
) -> None:
    from evidenceforge.studio.paths import StudioPaths
    from evidenceforge.studio.settings import SettingsStore, StudioSettings
    from evidenceforge.studio.store import StudioStore
    from evidenceforge.studio.windows_uninstall import _inventory

    root = locations.private
    store = StudioStore(root / "studio.sqlite")
    store.publish("fixture", "notification", {"message": "old private history"})
    store.close()
    paths = StudioPaths(
        config=root, data=root, state=root, cache=root / "cache", logs=root / "logs"
    )
    SettingsStore(paths).save(StudioSettings(workspace=locations.documents / "EvidenceForge"))
    publisher = write(
        locations.profile / ".eforge/publisher.yaml",
        "publisher: test\npublisher_display_name: Test\n",
    )
    before = _inventory(root)
    plan = build_plan(locations)
    execute(plan, {"skills"})
    assert not publisher.exists()
    assert _inventory(root) == before  # Ownership inspection must not add WAL/SHM or change bytes.
    execute(build_plan(locations), {"private"})
    assert not root.exists()
    fresh = StudioStore(root / "studio.sqlite")
    try:
        assert fresh._db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        assert not paths.settings_file.exists()
    finally:
        fresh.close()


def test_retained_wal_is_visible_to_probe_without_source_mutation(locations: UserLocations) -> None:
    import sqlite3
    import subprocess
    import sys

    from evidenceforge.studio.windows_uninstall import _check_workers_snapshot, _inventory

    database = locations.private / "studio.sqlite"
    database.parent.mkdir(parents=True)
    script = """
import os, sqlite3, sys
connection=sqlite3.connect(sys.argv[1])
connection.execute('PRAGMA journal_mode=WAL')
connection.execute('CREATE TABLE retained (value TEXT)')
connection.commit()
connection.execute("INSERT INTO retained VALUES ('committed only in WAL')")
connection.commit()
os._exit(0)
"""
    subprocess.run([sys.executable, "-c", script, str(database)], check=True, timeout=20)
    assert database.with_name("studio.sqlite-wal").is_file()
    before = _inventory(locations.private)

    def probe(snapshot: Path) -> None:
        assert snapshot != database
        connection = sqlite3.connect(snapshot.as_uri() + "?mode=ro", uri=True)
        try:
            assert (
                connection.execute("SELECT value FROM retained").fetchone()[0]
                == "committed only in WAL"
            )
        finally:
            connection.close()

    with patch("evidenceforge.studio.state_upgrade.check_workers", side_effect=probe):
        _check_workers_snapshot(database)
    assert _inventory(locations.private) == before


def test_private_only_cleanup_does_not_inspect_other_categories(locations: UserLocations) -> None:
    state = write(locations.private / "saved-state.txt")
    publisher = write(locations.profile / ".eforge/publisher.yaml", "not: [valid")
    settings = write(locations.private / "settings.json", "not-json")
    plan = build_plan(locations, {"private"})
    assert plan.targets and {target.category for target in plan.targets} == {"private"}
    assert state.exists() and publisher.exists() and settings.exists()
    assert build_plan(locations, set()).targets == ()


def test_cleanup_dialog_opens_before_inventory_and_prepares_only_selected_categories(
    locations: UserLocations, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.studio import windows_uninstall_native as native
    from evidenceforge.studio import windows_uninstall_ui as ui

    state = write(locations.private / "saved-state.txt")
    calls: list[set[Category]] = []
    monkeypatch.setattr(native, "user_locations", lambda: locations)

    def prepare(current: UserLocations, categories: set[Category]) -> CleanupPlan:
        calls.append(categories)
        return build_plan(current, categories)

    def choose(plan: CleanupPlan, *, prepare: Callable[[set[Category]], CleanupPlan]) -> int:
        assert calls == []
        assert plan.targets == () and plan.locations == locations
        assert prepare(set()).targets == ()
        selected = prepare({"private"})
        assert {target.category for target in selected.targets} == {"private"}
        return 0

    monkeypatch.setattr(native, "build_plan", prepare)
    monkeypatch.setattr(ui, "choose", choose)
    assert native.interactive(locations.account) == 0
    assert calls == [set(), {"private"}]
    assert state.read_text() == "preserve"


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL inspection")
def test_cleanup_settings_allow_read_grants_without_mutating_them(locations: UserLocations) -> None:
    import subprocess

    from evidenceforge.studio.state_io import atomic_write
    from evidenceforge.studio.state_upgrade import settings_document

    private_directory(locations.private)
    settings = locations.private / "settings.json"
    atomic_write(
        settings,
        json.dumps(
            {
                "schema_version": 4,
                "settings": {"workspace": str(locations.profile / "EvidenceForge")},
            }
        ).encode(),
    )
    subprocess.run(
        ["icacls", str(settings), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True
    )
    before = subprocess.run(["icacls", str(settings)], check=True, capture_output=True).stdout
    with pytest.raises(PermissionError, match="another principal"):
        settings_document(settings)
    assert build_plan(locations, {"work"}).locations == locations
    after = subprocess.run(["icacls", str(settings)], check=True, capture_output=True).stdout
    assert before == after

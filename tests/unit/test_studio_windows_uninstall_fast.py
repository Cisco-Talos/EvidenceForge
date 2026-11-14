"""Bounded root review and direct cleanup without inventory or per-file staging."""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

import pytest

from evidenceforge.studio import windows_uninstall as cleanup
from evidenceforge.studio import windows_uninstall_fast as fast
from evidenceforge.studio.state_io import StateLock, StudioStateError, private_directory
from evidenceforge.studio.windows_uninstall import (
    CleanupProgress,
    UserLocations,
    build_plan,
    execute,
)
from tests.unit.test_studio_uninstall_wizard import _locations


@pytest.fixture
def locations(tmp_path: Path) -> UserLocations:
    return _locations(tmp_path)


def write(path: Path, text: str = "test") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_root_review_never_walks_payload_and_removal_visits_each_directory_once(
    locations: UserLocations, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_directory(locations.private)
    for directory in range(20):
        for file in range(25):
            write(locations.private / f"runtimes/payload/lib-{directory}/file-{file}")

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Root cleanup must not inventory or stage files")

    monkeypatch.setattr(cleanup, "_inventory", forbidden)
    monkeypatch.setattr(cleanup, "_move", forbidden)
    original = fast._names
    listed: list[int] = []

    def names(descriptor: int) -> list[tuple[str, bool]]:
        listed.append(os.fstat(descriptor).st_ino)
        return original(descriptor)

    monkeypatch.setattr(fast, "_names", names)
    plan = build_plan(locations, {"private"}, root_review=True)
    assert not listed
    assert all(len(target.entries) == 1 for target in plan.targets)
    # Approval covers the selected folder's contents at removal, including additions.
    write(locations.private / "created-after-review")
    progress: list[CleanupProgress] = []
    execute(plan, {"private"}, report_progress=progress.append)
    assert not locations.private.exists()
    assert max(Counter(listed).values()) == 1
    assert {value.phase for value in progress} == {"removing", "complete"}
    assert all(value.total is None for value in progress[:-1])
    assert progress[-1].phase == "complete"
    assert not list(locations.profile.rglob(".eforge-uninstall-*"))


@pytest.mark.parametrize(
    "selected", [{"private"}, {"work"}, {"skills"}, {"private", "skills", "work"}]
)
def test_root_cleanup_preserves_unselected_shared_and_custom_content(
    locations: UserLocations, selected: set[str]
) -> None:
    private = write(locations.private / "settings.txt")
    workspace = locations.profile / "EvidenceForge"
    work = write(workspace / ".eforge/artifacts/drafts/test.yaml")
    manual = write(workspace / "manual.txt")
    publisher = write(
        locations.profile / ".eforge/publisher.yaml",
        "publisher: test\npublisher_display_name: Test\n",
    )
    sign_in = write(locations.profile / ".codex/auth.json")
    full = len(selected) == 3
    plan = build_plan(locations, selected, full_cleanup=full, root_review=True)
    execute(plan, selected)
    assert private.exists() is ("private" not in selected)
    assert work.exists() is ("work" not in selected)
    assert publisher.exists() is ("skills" not in selected)
    assert manual.exists() is (not full)
    assert sign_in.read_text() == "test"


def test_replaced_root_is_rejected_before_removing_any_selected_content(
    locations: UserLocations,
) -> None:
    private = write(locations.private / "preserve")
    workspace = locations.profile / "EvidenceForge"
    write(workspace / "old")
    plan = build_plan(locations, {"private", "skills", "work"}, full_cleanup=True, root_review=True)
    workspace.rename(workspace.with_name("moved"))
    replacement = write(workspace / "replacement")
    with pytest.raises(StudioStateError, match="root changed"):
        execute(plan, {"private", "skills", "work"})
    assert private.exists() and replacement.exists()


@pytest.mark.parametrize("kind", ["service", "run", "lease"])
def test_active_owner_is_refused_before_data_removal(locations: UserLocations, kind: str) -> None:
    from evidenceforge.generation.checkpoints.store import RunLock

    sentinel = write(locations.private / "preserve")
    workspace = locations.profile / "EvidenceForge"
    run = workspace / "runs/scenario/test/.eforge-generation"
    private_directory(run)
    plan = build_plan(locations, {"private", "skills", "work"}, full_cleanup=True, root_review=True)
    if kind == "run":
        owner = RunLock(run)
    elif kind == "lease":
        owner = StateLock(locations.private / "runtimes/leases/test.lock")
    else:
        owner = StateLock(locations.private / "service-instance.lock")
    with owner, pytest.raises(StudioStateError):
        execute(plan, {"private", "skills", "work"})
    assert sentinel.exists()


def test_descendant_link_never_deletes_its_external_target(locations: UserLocations) -> None:
    outside = write(locations.profile / "outside/secret")
    root = locations.private
    private_directory(root)
    if os.name == "nt":
        import subprocess

        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(root / "linked"), str(outside.parent)],
            check=True,
            capture_output=True,
        )
    else:
        (root / "linked").symlink_to(outside.parent, target_is_directory=True)
    plan = build_plan(locations, {"private"}, root_review=True)
    progress: list[CleanupProgress] = []
    with pytest.raises(StudioStateError):
        execute(plan, {"private"}, report_progress=progress.append)
    assert outside.read_text() == "test"
    assert not any(value.phase == "complete" for value in progress)


@pytest.mark.skipif(os.name != "nt", reason="Native read-only entries and deletion handles")
def test_native_readonly_tree_removal_opens_files_once_and_never_checks_descendant_acls(
    locations: UserLocations, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.utils import windows_filesystem as fs

    root = locations.private
    for index in range(30):
        file = write(root / f"payload/dir-{index}/file")
        file.chmod(0o400)
        file.parent.chmod(0o400)
    plan = build_plan(locations, {"private"}, root_review=True)
    opened: list[tuple[str, bool]] = []
    original = fs.open_cleanup_child

    def open_child(parent: int, name: str, *, directory: bool) -> int:
        opened.append((name, directory))
        return original(parent, name, directory=directory)

    monkeypatch.setattr(fs, "open_cleanup_child", open_child)
    execute(plan, {"private"})
    assert not root.exists()
    assert sum(name == "file" and not directory for name, directory in opened) == 30


def test_confirmation_is_only_the_question_selected_items_and_irreversibility(
    locations: UserLocations,
) -> None:
    text = cleanup.confirmation(cleanup.CleanupPlan(locations=locations), {"private", "work"})
    assert text == (
        "Are you sure you want to uninstall Studio and permanently delete the selected content?\n\n"
        f"• {cleanup.LABELS['private']}\n• {cleanup.LABELS['work']}\n\nThis cannot be undone."
    )
    assert str(locations.profile) not in text and "SID=" not in text


def test_content_created_after_writer_fences_close_is_preserved_without_rescanning(
    locations: UserLocations, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(locations.private / "old")
    plan = build_plan(locations, {"private"}, root_review=True)
    original = StateLock.close
    injected = False
    new = locations.private / "new-startup-content"

    def close(lock: StateLock) -> None:
        nonlocal injected
        original(lock)
        if not injected and lock.path.parent == locations.private:
            injected = True
            new.write_text("preserve")

    monkeypatch.setattr(StateLock, "close", close)
    progress: list[CleanupProgress] = []
    with pytest.raises(StudioStateError, match="application has not been uninstalled"):
        execute(plan, {"private"}, report_progress=progress.append)
    assert new.read_text() == "preserve"
    assert not any(value.phase == "complete" for value in progress)


@pytest.mark.skipif(os.name != "nt", reason="Native shared runtime lease interoperability")
def test_native_running_runtime_lease_blocks_cleanup_before_any_removal(
    locations: UserLocations,
) -> None:
    from evidenceforge.studio.windows_leases import lock_runtime

    sentinel = write(locations.private / "keep")
    lease = write(locations.private / "runtimes/leases/test.lock")
    descriptor = os.open(lease, os.O_RDONLY | os.O_BINARY)
    try:
        lock_runtime(descriptor, exclusive=False)
        plan = build_plan(locations, {"private"}, root_review=True)
        with pytest.raises(StudioStateError):
            execute(plan, {"private"})
        assert sentinel.exists()
    finally:
        os.close(descriptor)

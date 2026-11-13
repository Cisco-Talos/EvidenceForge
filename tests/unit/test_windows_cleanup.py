"""Temporary Windows deletion failures must remain bounded and observable."""

from pathlib import Path

import pytest

from evidenceforge import _windows_cleanup as cleanup
from evidenceforge import _windows_cleanup_native as native


@pytest.mark.parametrize("code", [5, 32, 33, 145])
def test_temporary_windows_delete_failure_retries_partial_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    first = root / "already-removed.txt"
    first.write_text("scratch")
    retained = root / "retained.txt"
    retained.write_text("scratch")
    real_remove = cleanup.shutil.rmtree
    attempts: list[Path] = []
    waits: list[float] = []

    def remove(path: Path) -> None:
        attempts.append(path)
        if len(attempts) == 1:
            first.unlink()
            error = PermissionError("temporary Windows delete failure")
            error.winerror = code
            raise error
        real_remove(path)

    monkeypatch.setattr(cleanup, "_WINDOWS", True)
    monkeypatch.setattr(cleanup.shutil, "rmtree", remove)
    monkeypatch.setattr(cleanup, "sleep", waits.append)
    cleanup.remove_temporary_tree(root)
    assert len(attempts) == 2 and waits == [cleanup._DELETE_RETRY_DELAYS[0]]
    assert not root.exists()


def test_persistent_windows_delete_failure_preserves_original_error_and_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    error = PermissionError("persistent access denial")
    error.winerror = 5
    attempts: list[Path] = []
    waits: list[float] = []

    def remove(path: Path) -> None:
        attempts.append(path)
        raise error

    monkeypatch.setattr(cleanup, "_WINDOWS", True)
    monkeypatch.setattr(cleanup.shutil, "rmtree", remove)
    monkeypatch.setattr(cleanup, "sleep", waits.append)
    with pytest.raises(PermissionError) as caught:
        cleanup.remove_temporary_tree(root)
    assert caught.value is error
    assert root.is_dir()
    assert len(attempts) == len(cleanup._DELETE_RETRY_DELAYS) + 1
    assert waits == list(cleanup._DELETE_RETRY_DELAYS)
    assert sum(waits) < 4


@pytest.mark.parametrize("windows,code", [(False, 5), (True, 87), (True, None)])
def test_unrelated_or_posix_removal_failure_does_not_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, windows: bool, code: int | None
) -> None:
    error = OSError("unrelated removal failure")
    if code is not None:
        error.winerror = code
    attempts: list[Path] = []
    waits: list[float] = []

    def remove(path: Path) -> None:
        attempts.append(path)
        raise error

    monkeypatch.setattr(cleanup, "_WINDOWS", windows)
    monkeypatch.setattr(cleanup.shutil, "rmtree", remove)
    monkeypatch.setattr(cleanup, "sleep", waits.append)
    with pytest.raises(OSError) as caught:
        cleanup.remove_temporary_tree(tmp_path / "owned")
    assert caught.value is error and len(attempts) == 1 and not waits


@pytest.mark.parametrize("variant", range(16))
def test_readonly_cloud_placeholder_is_not_a_name_redirection(variant: int) -> None:
    assert native._eligible_attributes(0x431, 0x9000001A | variant << 12)


@pytest.mark.parametrize("tag", [0, 0xA0000003, 0xA000000C, 0x9000001C, 0x80000021])
def test_unknown_or_redirecting_reparse_point_is_not_repaired(tag: int) -> None:
    assert not native._eligible_attributes(0x431, tag)


def test_plain_readonly_entry_only_and_outside_path_is_never_repaired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert native._eligible_attributes(0x31, 0)
    assert not native._eligible_attributes(0x30, 0)
    touched: list[Path] = []
    monkeypatch.setattr(
        native, "clear_readonly_for_removal", lambda path: touched.append(path) or True
    )
    root = cleanup.filesystem_path(tmp_path / "owned")
    outside = PermissionError(13, "denied", str(tmp_path / "unrelated"))
    outside.winerror = 5
    assert not cleanup._repair_readonly_entry(root, outside)
    assert not touched
    inside = PermissionError(13, "denied", str(root / "scratch"))
    inside.winerror = 5
    assert cleanup._repair_readonly_entry(root, inside)
    assert touched == [root / "scratch"]

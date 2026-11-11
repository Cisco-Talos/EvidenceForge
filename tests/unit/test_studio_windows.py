"""Windows payload validation, native discovery and launch-option contracts."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from evidenceforge.studio import processes, runtime
from evidenceforge.studio.state_io import StudioStateError
from evidenceforge.studio.windows_runtime import WindowsManifest, payload_path


@pytest.mark.parametrize(
    "name", ["../escape", "/absolute", "C:/drive", "a\\b", "NUL", "x./a", "a:stream", "COM1.txt"]
)
def test_payload_rejects_windows_aliases_and_traversal(name: str) -> None:
    with pytest.raises(StudioStateError):
        payload_path(name)


def test_windows_manifest_rejects_other_architecture_or_archive_path() -> None:
    with pytest.raises(ValueError):
        WindowsManifest.model_validate(
            {
                "schema_version": 1,
                "evidenceforge_version": "3.0.0rc1",
                "python_version": "3.12.12",
                "minimum_windows": "Windows 11",
                "runtimes": {"x86_64": {"archive": "../payload", "sha256": "a" * 64}},
            }
        )


def test_npm_discovery_uses_native_binary_without_executing_a_shim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime.sys, "platform", "win32")
    shim = tmp_path / "codex.cmd"
    native = (
        tmp_path
        / "node_modules/@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/codex/codex.exe"
    )
    native.parent.mkdir(parents=True)
    native.write_bytes(b"native fixture")
    monkeypatch.setenv("EFORGE_DESKTOP_CODEX_BIN", str(shim))
    assert runtime.discover_codex() == str(native)
    native.unlink()
    assert runtime.discover_codex() is None


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows kernel lease and launch flags")
def test_native_windows_shared_lease_blocks_exclusive_until_every_owner_closes(
    tmp_path: Path,
) -> None:
    from evidenceforge.studio.runtime_cleanup import _lease
    from evidenceforge.studio.state_io import private_directory

    root = tmp_path / "runtimes" / f"{'a' * 64}-x86_64"
    private_directory(root)
    first = _lease(root, exclusive=False)
    second = _lease(root, exclusive=False)
    try:
        with pytest.raises(BlockingIOError):
            _lease(root, exclusive=True)
        os.close(first)
        first = -1
        with pytest.raises(BlockingIOError):
            _lease(root, exclusive=True)
    finally:
        if first != -1:
            os.close(first)
        os.close(second)
    os.close(_lease(root, exclusive=True))
    options = processes.launch_options(detached=True)
    assert options["creationflags"] & 0x08000000
    assert options["creationflags"] & 0x00000200
    assert "pass_fds" not in options and "start_new_session" not in options


@pytest.mark.skipif(sys.platform != "win32", reason="Windows preview retention policy")
def test_native_windows_cleanup_retains_every_runtime_without_posix_operations(
    tmp_path: Path,
) -> None:
    from evidenceforge.studio.runtime_cleanup import RuntimeCleanup, RuntimeCleanupSettings

    root = tmp_path / "runtimes" / f"{'a' * 64}-x86_64"
    root.mkdir(parents=True)
    marker = root / "keep.txt"
    marker.write_text("retained")
    manager = RuntimeCleanup(tmp_path, root)
    report = manager.clean(now=10**12)
    assert not report.available and report.unavailable_reason and not report.removed
    assert marker.read_text() == "retained"
    with pytest.raises(StudioStateError, match="unavailable"):
        manager.save_settings(RuntimeCleanupSettings(previous_runtime_days=0))

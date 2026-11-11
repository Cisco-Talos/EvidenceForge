"""Windows payload validation, native discovery and launch-option contracts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidenceforge.studio import processes, runtime
from evidenceforge.studio.state_io import StudioStateError
from evidenceforge.studio.windows_runtime import WindowsManifest, payload_path


def test_cli_lease_preserves_a_read_only_runtime_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.studio.runtime import RuntimeRelease
    from evidenceforge.studio.runtime_cleanup import _lease, runtime_lease
    from evidenceforge.studio.state_io import atomic_write, private_directory

    root = tmp_path / "runtimes" / f"{'a' * 64}-x86_64"
    private_directory(root)
    release = RuntimeRelease(
        runtime_id="a" * 64,
        architecture="x86_64",
        evidenceforge_version="3.0.0rc1",
        python_version="3.12.12",
    )
    atomic_write(root / "release.json", release.model_dump_json().encode())
    os.close(_lease(root, exclusive=False))
    lease = root.parent / "leases" / f"{root.name}.lock"
    install = root.parent / "install.lock"
    atomic_write(install, b"unchanged")
    monkeypatch.setenv("EFORGE_STUDIO_RUNTIME_ROOT", str(root))
    lease.chmod(0o400)
    install.chmod(0o400)
    try:
        with runtime_lease(read_only=True):
            with pytest.raises(BlockingIOError):
                _lease(root, exclusive=True, create=False)
        os.close(_lease(root, exclusive=True, create=False))
        assert install.read_bytes() == b"unchanged"
    finally:
        lease.chmod(0o600)
        install.chmod(0o600)


def test_isolated_windows_python_uses_utf8_independently_of_user_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(processes, "os", SimpleNamespace(name="nt"))
    result = subprocess.run(
        [
            sys.executable,
            *processes.isolated_python_options(),
            "-c",
            "import sys; assert sys.flags.utf8_mode == 1; print('漢')",
        ],
        env={**os.environ, "PYTHONUTF8": "0", "PYTHONIOENCODING": "ascii"},
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
    )
    assert result.stdout == "漢\n"


def test_ordinary_cli_does_not_import_optional_studio_dependencies() -> None:
    script = """
import importlib.abc, runpy, sys
class RejectStudio(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'evidenceforge.studio' or fullname.startswith('evidenceforge.studio.'):
            raise AssertionError('Ordinary CLI imported optional Studio dependencies')
sys.meta_path.insert(0, RejectStudio())
sys.argv = ['eforge', '--help']
runpy.run_module('evidenceforge', run_name='__main__')
"""
    environment = dict(os.environ)
    environment.pop("EFORGE_STUDIO_RUNTIME_ROOT", None)
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "Usage" in result.stdout


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows concurrent publication")
def test_native_job_records_remain_readable_during_controller_replacement(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from evidenceforge.desktop.job_store import ControlIntent, JobStore

    store = JobStore(tmp_path / "private")
    store.write_control(ControlIntent(id="initial", action="open"))
    start = Barrier(2, timeout=10)
    expected = {"initial"} | {f"revision-{index}" for index in range(75)}

    def write() -> None:
        start.wait()
        for index in range(75):
            store.write_control(ControlIntent(id=f"revision-{index}", action="resume"))

    def read() -> None:
        start.wait()
        for _ in range(300):
            assert store.read_control().id in expected

    with ThreadPoolExecutor(max_workers=2) as pool:
        writer, reader = pool.submit(write), pool.submit(read)
        writer.result(timeout=30)
        reader.result(timeout=30)
    assert store.read_control().id == "revision-74"


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows authoring shell")
def test_authoring_prefix_round_trips_arguments_in_native_powershell() -> None:
    arguments = [r"C:\space ü\author's scenario.yaml", "literal;$env:USERNAME"]
    prefix = processes.shell_command(
        [sys.executable, "-c", "import json,sys;print(json.dumps(sys.argv[1:]))", *arguments]
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", prefix],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
        env={**os.environ, "PYTHONUTF8": "1"},
    )
    assert json.loads(result.stdout) == arguments


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


@pytest.mark.parametrize(
    "package",
    [
        "node_modules/@openai/codex",
        "node_modules/@openai/codex-win32-x64",
        "node_modules/@openai/codex/node_modules/@openai/codex-win32-x64",
    ],
)
@pytest.mark.parametrize("directory", ["bin", "codex"])
def test_npm_discovery_uses_native_binary_without_executing_a_shim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    package: str,
    directory: str,
) -> None:
    monkeypatch.setattr(runtime.sys, "platform", "win32")
    shim = tmp_path / "codex.cmd"
    native = tmp_path / package / "vendor/x86_64-pc-windows-msvc" / directory / "codex.exe"
    native.parent.mkdir(parents=True)
    native.write_bytes(b"native fixture")
    monkeypatch.setenv("EFORGE_DESKTOP_CODEX_BIN", str(shim))
    assert runtime.discover_codex() == str(native)
    native.unlink()
    assert runtime.discover_codex() is None


def test_explicit_python_command_preserves_arguments_without_shell_associations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "configured command ü.py"
    script.write_text("import json,sys; print(json.dumps(sys.argv[1:]))", encoding="utf-8")
    monkeypatch.setattr(processes, "os", SimpleNamespace(name="nt"))
    arguments = ["two words", "ü & literal", "$(literal)"]
    result = subprocess.run(
        [*processes.executable_command(script), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    import json

    assert json.loads(result.stdout) == arguments


def test_windows_protocol_fixture_responds_to_preflight_before_transport_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.support import studio_executable

    script = tmp_path / "fake-codex"
    script.write_text(
        "import json,sys\nfor line in sys.stdin:\n    request = json.loads(line)\n    print(json.dumps({'id': request['id'], 'result': {}}), flush=True)\n"
    )
    monkeypatch.setattr(studio_executable, "os", SimpleNamespace(name="nt"))
    prepared = studio_executable.prepare_script(script, codex=True)
    result = subprocess.run(
        [sys.executable, str(prepared)],
        input='{"id":1,"method":"windowsSandbox/readiness"}\n',
        check=True,
        capture_output=True,
        text=True,
    )
    import json

    assert json.loads(result.stdout) == {"id": 1, "result": {"status": "ready"}}


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

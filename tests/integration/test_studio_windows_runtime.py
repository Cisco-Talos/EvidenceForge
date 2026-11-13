"""Native private payload installation and interrupted-publication recovery."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue
from threading import Thread
from typing import IO

import pytest

from evidenceforge.studio.state_io import StudioStateError
from evidenceforge.studio.windows_runtime import install_runtime

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="Native Windows payload publication"
)


def resources(root: Path, *, malicious: bool = False, content: bytes = b"fixture") -> Path:
    source = root / "resources"
    source.mkdir()
    archive = source / "runtime-x86_64.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        for name in ("python.exe", "Scripts/eforge.exe", "Lib/site-packages/fixture.txt"):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            stream.addfile(info, io.BytesIO(content))
        if malicious:
            info = tarfile.TarInfo("../escape")
            stream.addfile(info, io.BytesIO())
    (source / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "evidenceforge_version": "3.0.0rc1",
                "python_version": "3.12.12",
                "minimum_windows": "Windows 11",
                "runtimes": {
                    "x86_64": {
                        "archive": archive.name,
                        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    }
                },
            }
        )
    )
    return source


def test_install_is_private_repeatable_and_preserves_interrupted_staging(tmp_path: Path) -> None:
    import os

    from evidenceforge.utils.windows_filesystem import open_directory, require_private

    source = resources(tmp_path)
    data = tmp_path / "data ü"
    root = install_runtime(source, data)
    assert install_runtime(source, data) == root
    descriptor = open_directory(root)
    try:
        require_private(descriptor)
    finally:
        os.close(descriptor)
    interrupted = data / "runtimes/.install-interrupted"
    interrupted.mkdir()
    (interrupted / "partial").write_text("preserve")
    assert install_runtime(source, data) == root
    assert (interrupted / "partial").read_text() == "preserve"
    (root / "release.json").write_text("{}")
    with pytest.raises(ValueError):
        install_runtime(source, data)


def test_runtime_progress_distinguishes_first_setup_update_and_repeat_launch(
    tmp_path: Path,
) -> None:
    first_source = tmp_path / "first"
    second_source = tmp_path / "second"
    first_source.mkdir()
    second_source.mkdir()
    data = tmp_path / "private"
    events: list[tuple[str, str, int | None]] = []

    def progress(title: str, detail: str, percent: int | None) -> None:
        events.append((title, detail, percent))

    source = resources(first_source)
    first = install_runtime(source, data, progress)
    assert any(title == "Doing first-time setup" for title, _, _ in events)
    assert events[-1][-1] == 100
    events.clear()
    assert install_runtime(source, data, progress) == first
    assert {title for title, _, _ in events} == {"Starting Studio"}
    events.clear()
    second = install_runtime(resources(second_source, content=b"new payload"), data, progress)
    assert second != first and first.is_dir()
    assert any(title == "Updating Studio" for title, _, _ in events)
    assert events[-1][-1] == 100


def test_checksum_or_traversal_never_publishes_runtime(tmp_path: Path) -> None:
    source = resources(tmp_path, malicious=True)
    data = tmp_path / "data"
    with pytest.raises(StudioStateError, match="alias"):
        install_runtime(source, data)
    assert not (data / "runtimes/escape").exists()
    assert not list((data / "runtimes").glob("*-x86_64"))
    (source / "runtime-x86_64.tar.gz").write_bytes(b"corrupted")
    with pytest.raises(StudioStateError, match="checksum"):
        install_runtime(source, data)


def test_concurrent_first_install_publishes_one_complete_runtime(tmp_path: Path) -> None:
    from threading import Barrier

    source = resources(tmp_path)
    data = tmp_path / "concurrent data"
    start = Barrier(2, timeout=10)

    def install() -> Path:
        start.wait()
        return install_runtime(source, data)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.submit(install), pool.submit(install)
        roots = [first.result(timeout=30), second.result(timeout=30)]
    assert roots[0] == roots[1]
    assert (roots[0] / "release.json").is_file()
    assert len(list((data / "runtimes").glob("*-x86_64"))) == 1


def test_runtime_replacement_preserves_a_live_workers_cross_process_lease(tmp_path: Path) -> None:
    from evidenceforge.studio.runtime_cleanup import _lease

    first_source = tmp_path / "first"
    second_source = tmp_path / "second"
    first_source.mkdir()
    second_source.mkdir()
    data = tmp_path / "private data"
    first = install_runtime(resources(first_source), data)
    script = (
        "import os,sys\nfrom pathlib import Path\n"
        "from evidenceforge.studio.runtime_cleanup import _lease\n"
        "root=Path(sys.argv[1]); fd=_lease(root,exclusive=False)\n"
        "print('ready',flush=True); sys.stdin.readline()\n"
        "assert (root/'Lib/site-packages/fixture.txt').read_bytes()==b'fixture'\n"
        "os.close(fd)\n"
    )
    with subprocess.Popen(
        [sys.executable, "-c", script, str(first)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    ) as worker:
        assert worker.stdout is not None and worker.stdin is not None
        ready: Queue[str] = Queue()
        Thread(target=lambda: ready.put(worker.stdout.readline()), daemon=True).start()
        try:
            assert ready.get(timeout=15).strip() == "ready"
            second = install_runtime(resources(second_source, content=b"replacement"), data)
            assert second != first
            assert (first / "release.json").is_file()
            with pytest.raises(BlockingIOError):
                _lease(first, exclusive=True)
        finally:
            worker.stdin.write("finish\n")
            worker.stdin.flush()
            assert worker.wait(timeout=15) == 0
    os.close(_lease(first, exclusive=True))


def test_interrupted_extraction_can_retry_without_publishing_partial_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = resources(tmp_path)
    data = tmp_path / "private"
    original: Callable[..., IO[bytes] | None] = tarfile.TarFile.extractfile
    count = 0

    def interrupt(archive: tarfile.TarFile, member: tarfile.TarInfo) -> IO[bytes] | None:
        nonlocal count
        count += 1
        if count == 2:
            raise OSError("injected extraction interruption")
        return original(archive, member)

    with monkeypatch.context() as fault:
        fault.setattr(tarfile.TarFile, "extractfile", interrupt)
        with pytest.raises(OSError, match="interruption"):
            install_runtime(source, data)
    assert not list((data / "runtimes").glob("*-x86_64"))
    interrupted = list((data / "runtimes").glob(".install-*"))
    assert len(interrupted) == 1
    assert (interrupted[0] / "python.exe").is_file()
    complete = install_runtime(source, data)
    assert (complete / "Scripts/eforge.exe").is_file()
    assert (complete / "release.json").is_file()
    assert interrupted[0].is_dir()

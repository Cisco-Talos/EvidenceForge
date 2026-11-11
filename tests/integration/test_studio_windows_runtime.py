"""Native private payload installation and interrupted-publication recovery."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

from evidenceforge.studio.state_io import StudioStateError
from evidenceforge.studio.windows_runtime import install_runtime

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="Native Windows payload publication"
)


def resources(root: Path, *, malicious: bool = False) -> Path:
    source = root / "resources"
    source.mkdir()
    archive = source / "runtime-x86_64.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        for name in ("python.exe", "Scripts/eforge.exe", "Lib/site-packages/fixture.txt"):
            info = tarfile.TarInfo(name)
            info.size = 7
            stream.addfile(info, io.BytesIO(b"fixture"))
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

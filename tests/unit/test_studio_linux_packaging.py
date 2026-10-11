"""Native Tauri bundle discovery and public Linux installer naming contracts."""

from pathlib import Path
from unittest.mock import Mock

import pytest
from scripts import package_studio_linux as packaging


@pytest.mark.parametrize(
    ("architecture", "native_filename"),
    [
        ("x86_64", "EvidenceForge Studio_2.2.0-alpha.2_amd64.AppImage"),
        ("aarch64", "EvidenceForge Studio_2.2.0-alpha.2_aarch64.AppImage"),
    ],
)
@pytest.mark.parametrize("release", [False, True])
def test_native_tauri_bundles_become_versioned_installer_checksum_pairs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    architecture: str,
    native_filename: str,
    release: bool,
) -> None:
    root = tmp_path / "checkout"
    native = root / "desktop-ui/src-tauri"
    native.mkdir(parents=True)
    (native / "Cargo.toml").write_text('[package]\nversion = "2.2.0-alpha.2"\n')
    (root / "pyproject.toml").write_text('[project]\nversion = "2.2.0a2"\n')
    build = tmp_path / "build"
    bundle = build / "target" / f"{architecture}-unknown-linux-gnu/release/bundle/appimage"
    bundle.mkdir(parents=True)
    image = bundle / native_filename
    image.write_bytes(b"native Tauri installer fixture")
    monkeypatch.setattr(packaging, "run", Mock(return_value=None))

    installer = packaging.build_appimage(
        root, build, build / "configuration.json", architecture, release=release
    )

    suffix = "" if release else "-test"
    assert installer.name == f"EvidenceForge-Studio-2.2.0a2-{architecture}{suffix}.AppImage"
    assert installer.read_bytes() == image.read_bytes()
    assert installer.stat().st_mode & 0o111 == 0o111
    assert installer.with_suffix(".AppImage.sha256").read_text() == (
        f"{packaging.digest(image)}  {installer.name}\n"
    )

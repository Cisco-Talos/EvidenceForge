"""Build a native Linux AppImage with Studio's retained private Python runtime."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import sys
import tomllib
from pathlib import Path

if __package__:
    from .package_studio_macos import assemble, digest, run
else:
    from package_studio_macos import assemble, digest, run


def build_appimage(
    root: Path, build: Path, configuration: Path, architecture: str, *, release: bool = False
) -> Path:
    """Bundle on the native architecture, keeping installer outputs out of the checkout."""
    target = f"{architecture}-unknown-linux-gnu"
    environment = {
        **os.environ,
        "CARGO_TARGET_DIR": str(build / "target"),
        "CARGO_BUILD_JOBS": os.environ.get("CARGO_BUILD_JOBS", "2"),
        # AppImage build tools also offer extraction when the builder has no FUSE mount.
        "APPIMAGE_EXTRACT_AND_RUN": "1",
    }
    frontend = root / "desktop-ui"
    run(
        [
            "node",
            str(frontend / "node_modules/@tauri-apps/cli/tauri.js"),
            "build",
            "--target",
            target,
            "--config",
            str(configuration),
            "--bundles",
            "appimage",
            "--",
            "--locked",
        ],
        frontend,
        environment,
    )
    native_version = tomllib.loads((root / "desktop-ui/src-tauri/Cargo.toml").read_text())[
        "package"
    ]["version"]
    # Tauri names x86_64 Linux bundles with Debian's amd64 architecture spelling.
    bundle_architecture = "amd64" if architecture == "x86_64" else architecture
    artifacts = list(
        (build / "target" / target / "release/bundle/appimage").glob(
            f"*_{native_version}_{bundle_architecture}.AppImage"
        )
    )
    if len(artifacts) != 1:
        raise RuntimeError(
            f"Expected one AppImage for {native_version}/{architecture}: {artifacts}"
        )
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    destination = root / "dist/linux"
    destination.mkdir(parents=True, exist_ok=True)
    suffix = "" if release else "-test"
    installer = destination / f"EvidenceForge-Studio-{version}-{architecture}{suffix}.AppImage"
    # A preview may still be mounted or running; preserve its inode until users close it.
    temporary = installer.with_suffix(".AppImage.part")
    shutil.copy2(artifacts[0], temporary)
    temporary.chmod(0o755)
    temporary.replace(installer)
    installer.with_suffix(".AppImage.sha256").write_text(f"{digest(installer)}  {installer.name}\n")
    print(f"AppImage: {installer}", flush=True)
    return installer


def main() -> None:
    """Assemble/build locally; never tag, upload or publish the resulting installer."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", choices=["aarch64", "x86_64"])
    parser.add_argument("--build-directory", type=Path)
    parser.add_argument("--assemble-only", action="store_true")
    parser.add_argument("--release", action="store_true", help="Use release installer filenames")
    arguments = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Build AppImages on a native Linux machine")
    host = platform.machine()
    architecture = arguments.architecture or host
    if architecture not in {"aarch64", "x86_64"} or architecture != host:
        parser.error("The AppImage architecture must match the native Linux builder")
    if not arguments.assemble_only and shutil.which("patchelf") is None:
        parser.error(
            "AppImage GStreamer bundling requires patchelf; install your distribution's "
            "patchelf package (Ubuntu: sudo apt-get install patchelf)"
        )
    root = Path(__file__).resolve().parents[1]
    build = (arguments.build_directory or root / "build/studio-linux").resolve()
    configuration = assemble(root, build, [architecture], platform="linux")
    if not arguments.assemble_only:
        build_appimage(root, build, configuration, architecture, release=arguments.release)


if __name__ == "__main__":
    main()

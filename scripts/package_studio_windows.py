"""Build the unsigned dual-scope NSIS preview on native Windows x86_64."""

from __future__ import annotations

import argparse
import json
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


def main() -> None:
    """Assemble/build a preview without release credentials, tags or publication."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-directory", type=Path)
    parser.add_argument("--assemble-only", action="store_true")
    arguments = parser.parse_args()
    if sys.platform != "win32" or platform.machine().lower() not in {"amd64", "x86_64"}:
        parser.error("Build this preview on native Windows x86_64")
    root = Path(__file__).resolve().parents[1]
    build = (arguments.build_directory or root / "build/studio-windows").resolve()
    config = assemble(root, build, ["x86_64"], platform="windows")
    if arguments.assemble_only:
        return
    environment = {**os.environ, "CARGO_TARGET_DIR": str(build / "target")}
    frontend = root / "desktop-ui"
    run(
        [
            "node",
            str(frontend / "node_modules/@tauri-apps/cli/tauri.js"),
            "build",
            "--target",
            "x86_64-pc-windows-msvc",
            "--config",
            str(config),
            "--bundles",
            "nsis",
            "--no-sign",
            "--",
            "--locked",
        ],
        frontend,
        environment,
    )
    candidates = list(
        (build / "target/x86_64-pc-windows-msvc/release/bundle/nsis").glob("*-setup.exe")
    )
    if len(candidates) != 1:
        raise RuntimeError(f"Expected exactly one NSIS installer, found {candidates}")
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    destination = root / "dist/windows"
    destination.mkdir(parents=True, exist_ok=True)
    installer = destination / f"EvidenceForge-Studio-{version}-windows-x86_64-test-setup.exe"
    shutil.copy2(candidates[0], installer)
    installer.with_suffix(".exe.sha256").write_text(
        f"{digest(installer)}  {installer.name}\n", encoding="utf-8"
    )
    print(json.dumps({"installer": str(installer), "sha256": digest(installer)}), flush=True)


if __name__ == "__main__":
    main()

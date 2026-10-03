"""Assemble private runtimes and optionally build the standalone macOS app/DMG.

Run with ``uv run python scripts/package_studio_macos.py --build-app`` on macOS.
Build tools and downloads are used only on the build machine, never at app launch.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tomllib
import urllib.request
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class RuntimeArchive(BaseModel):
    """Pinned upstream interpreter archive."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    url: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class RuntimeLock(BaseModel):
    """Build inputs shared by local and CI assembly."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    python_version: str
    minimum_macos: str
    runtimes: dict[str, RuntimeArchive]


def run(command: list[str], root: Path, environment: dict[str, str]) -> None:
    """Run a build command, surfacing its own output and failures."""
    subprocess.run(command, cwd=root, env=environment, check=True)


def digest(path: Path) -> str:
    """Hash an archive without loading it into memory."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download(archive: RuntimeArchive, destination: Path) -> None:
    """Cache only a checksum-verified upstream archive."""
    if destination.is_file() and digest(destination) == archive.sha256:
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".part")
    try:
        with urllib.request.urlopen(archive.url, timeout=60) as source, temporary.open("wb") as out:
            shutil.copyfileobj(source, out)
        if digest(temporary) != archive.sha256:
            raise ValueError(f"Python runtime checksum mismatch: {archive.url}")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def pack_payload(root: Path, destination: Path) -> None:
    """Write stable archive ordering, metadata and gzip headers."""
    with destination.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(root.rglob("*")):
                    if "__pycache__" in path.parts or path.suffix == ".pyc":
                        continue
                    info = archive.gettarinfo(str(path), arcname=path.relative_to(root).as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = 0
                    info.pax_headers = {}
                    if info.isfile():
                        with path.open("rb") as source:
                            archive.addfile(info, source)
                    else:
                        archive.addfile(info)


def assemble(root: Path, build: Path, architectures: list[str]) -> Path:
    """Assemble selected runtime payloads from the lockfile and built project wheel."""
    lock = RuntimeLock.model_validate_json(
        (root / "desktop-ui/packaging/runtime-lock.json").read_bytes()
    )
    version: str = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    environment = {
        **os.environ,
        "UV_CACHE_DIR": str(build / "uv-cache"),
        "MACOSX_DEPLOYMENT_TARGET": lock.minimum_macos,
    }
    build.mkdir(parents=True, exist_ok=True)
    requirements = build / "runtime-requirements.txt"
    run(
        [
            "uv",
            "export",
            "--quiet",
            "--frozen",
            "--extra",
            "studio",
            "--no-dev",
            "--no-emit-project",
            "--no-header",
            "--output-file",
            str(requirements),
        ],
        root,
        environment,
    )
    wheels = build / "wheel"
    wheels.mkdir(exist_ok=True)
    run(["uv", "build", "--wheel", "--out-dir", str(wheels)], root, environment)
    wheel = wheels / f"evidence_forge-{version}-py3-none-any.whl"
    if not wheel.is_file():
        raise FileNotFoundError(f"Expected project wheel at {wheel}")
    resources = build / "resources"
    resources.mkdir(exist_ok=True)
    archives: dict[str, dict[str, str]] = {}
    for architecture in architectures:
        source = lock.runtimes[architecture]
        downloaded = build / "downloads" / f"python-{architecture}.tar.gz"
        download(source, downloaded)
        staging = build / "payloads" / architecture
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True)
        with tarfile.open(downloaded) as archive:
            archive.extractall(staging, filter="data")
        payload = staging / "python"
        packages = payload / "lib/python3.12/site-packages"
        run(
            [
                "uv",
                "pip",
                "install",
                "--target",
                str(packages),
                "--python-version",
                lock.python_version,
                "--python-platform",
                f"{architecture}-apple-darwin",
                "--only-binary",
                ":all:",
                "--require-hashes",
                "--no-compile-bytecode",
                "-r",
                str(requirements),
            ],
            root,
            environment,
        )
        run(
            [
                "uv",
                "pip",
                "install",
                "--target",
                str(packages),
                "--no-deps",
                "--no-compile-bytecode",
                str(wheel),
            ],
            root,
            environment,
        )
        # uv target installs console scripts with build-machine shebangs. Replace them
        # with the one public command required by Studio's authoring process.
        scripts = packages / "bin"
        if scripts.exists():
            shutil.rmtree(scripts)
        for metadata in packages.glob("evidence_forge-*.dist-info/direct_url.json"):
            metadata.unlink()
        command = payload / "bin/eforge"
        command.write_text(
            "#!/bin/sh\n"
            'task_runtime_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd) || exit 1\n'
            'exec "$task_runtime_dir/bin/python3.12" -I -B -m evidenceforge "$@"\n',
            encoding="utf-8",
        )
        command.chmod(0o755)
        notices = payload / "THIRD_PARTY_NOTICES.txt"
        notices.write_text(
            "EvidenceForge Studio test package\n\n"
            "CPython is distributed by python-build-standalone. Runtime license files are "
            "included under share/. Package licenses and metadata are retained in the "
            "site-packages *.dist-info directories.\n\n"
            f"Python archive: {source.url}\nSHA256: {source.sha256}\n\n"
            + (root / "LICENSE").read_text(),
            encoding="utf-8",
        )
        target = resources / f"runtime-{architecture}.tar.gz"
        pack_payload(payload, target)
        archives[architecture] = {"archive": target.name, "sha256": digest(target)}
        print(f"Assembled {architecture}: {target.stat().st_size / 1024**2:.1f} MiB", flush=True)
    manifest = {
        "schema_version": 1,
        "evidenceforge_version": version,
        "python_version": lock.python_version,
        "minimum_macos": lock.minimum_macos,
        "runtimes": archives,
    }
    (resources / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    configuration = build / "tauri-standalone.json"
    configuration.write_text(
        json.dumps(
            {
                "version": version,
                "bundle": {
                    "resources": {str(resources): "runtime"},
                    "macOS": {"minimumSystemVersion": lock.minimum_macos},
                },
            },
            indent=2,
        )
        + "\n"
    )
    return configuration


def build_app(root: Path, build: Path, configuration: Path, architectures: list[str]) -> None:
    """Build a native shell and create a drag-to-Applications test DMG."""
    if sys.platform != "darwin":
        raise RuntimeError("The macOS application must be built on macOS")
    lock = RuntimeLock.model_validate_json(
        (root / "desktop-ui/packaging/runtime-lock.json").read_bytes()
    )
    target = (
        "universal-apple-darwin" if len(architectures) == 2 else f"{architectures[0]}-apple-darwin"
    )
    environment = {
        **os.environ,
        "MACOSX_DEPLOYMENT_TARGET": lock.minimum_macos,
        "CARGO_TARGET_DIR": str(build / "target"),
    }
    # This artifact intentionally has no Developer ID identity or notarization.
    for name in list(environment):
        if name.startswith("APPLE_"):
            del environment[name]
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
            "app",
            "--no-sign",
            "--",
            "--locked",
        ],
        frontend,
        environment,
    )
    app = build / "target" / target / "release/bundle/macos/EvidenceForge Studio.app"
    run(
        [
            "xcrun",
            "swift",
            "-module-cache-path",
            str(build / "swift-cache"),
            str(frontend / "scripts/set-macos-app-icon.swift"),
            str(app),
            str(frontend / "src-tauri/icons/icon.icns"),
        ],
        root,
        environment,
    )
    destination = root / "dist/macos"
    destination.mkdir(parents=True, exist_ok=True)
    volume = build / "dmg-volume"
    if volume.exists():
        shutil.rmtree(volume)
    volume.mkdir()
    # The custom transparent Finder icon lives in resource forks/Finder metadata.
    # Python's macOS copytree drops them even though it copies the empty Icon file.
    run(
        ["/usr/bin/ditto", "--rsrc", "--extattr", str(app), str(volume / app.name)],
        root,
        environment,
    )
    (volume / "Applications").symlink_to("/Applications", target_is_directory=True)
    version: str = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    label = "universal" if len(architectures) == 2 else architectures[0]
    dmg = destination / f"EvidenceForge-Studio-{version}-{label}-test.dmg"
    run(
        [
            "hdiutil",
            "create",
            "-ov",
            "-format",
            "UDZO",
            "-volname",
            "EvidenceForge Studio",
            "-srcfolder",
            str(volume),
            str(dmg),
        ],
        root,
        environment,
    )
    (dmg.with_suffix(".dmg.sha256")).write_text(f"{digest(dmg)}  {dmg.name}\n")
    print(f"Standalone app: {app}\nTest DMG: {dmg}", flush=True)


def main() -> None:
    """Parse build options; Apple Silicon is the first supported test artifact."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--architectures", nargs="+", choices=["aarch64", "x86_64"], default=["aarch64"]
    )
    parser.add_argument("--build-app", action="store_true")
    parser.add_argument("--build-directory", type=Path)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build = (arguments.build_directory or root / "build/studio-macos").resolve()
    architectures = list(dict.fromkeys(arguments.architectures))
    configuration = assemble(root, build, architectures)
    if arguments.build_app:
        build_app(root, build, configuration, architectures)


if __name__ == "__main__":
    main()

"""Verify a packaged runtime from a relocated app without development PATH entries."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path


def main() -> None:
    """Inspect the artifact and exercise its installed CLI/resources in isolation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    arguments = parser.parse_args()
    app = arguments.app.resolve()
    resources = app / "Contents/Resources/runtime"
    manifest = json.loads((resources / "manifest.json").read_text())
    architecture = "aarch64" if platform.machine() == "arm64" else "x86_64"
    selected = manifest["runtimes"][architecture]
    archive = resources / selected["archive"]
    with archive.open("rb") as source:
        assert hashlib.file_digest(source, "sha256").hexdigest() == selected["sha256"]
    with tempfile.TemporaryDirectory(prefix="eforge standalone ü ") as temporary:
        root = Path(temporary).resolve()
        runtime = root / "runtime"
        runtime.mkdir()
        with tarfile.open(archive) as source:
            source.extractall(runtime, filter="data")
        workspace = root / "workspace"
        workspace.mkdir()
        environment = {
            **os.environ,
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONHOME": "/deliberately/unavailable/python",
            "PYTHONPATH": "/deliberately/unavailable/packages",
        }
        # A packaged command must not depend on a source-run override inherited
        # from the developer's terminal or a Python installation on PATH.
        for name in list(environment):
            if name.startswith("EFORGE_"):
                del environment[name]
        cli = runtime / "bin/eforge"
        commands = [
            [str(cli), "version"],
            [str(cli), "schema", "environment", "--json"],
            [str(cli), "pack", "list", "--json"],
            [str(cli), "install-skills", "--agent", "chatgpt"],
        ]
        for command in commands:
            result = subprocess.run(
                command, cwd=workspace, env=environment, capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Packaged CLI failed: {command[1:]}\n{result.stderr}\n{result.stdout}"
                )
        assert any((workspace / ".agents/skills").rglob("SKILL.md"))
        assert any((workspace / ".agents/skills").rglob("scenario-core.md"))
        fixture = Path(__file__).resolve().parents[1] / "tests/fixtures/scenarios/minimal.yaml"
        scenario = workspace / "scenario.yaml"
        shutil.copyfile(fixture, scenario)
        result = subprocess.run(
            [str(cli), "validate", str(scenario), "--json"],
            cwd=workspace,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Packaged validation failed: {result.stdout}\n{result.stderr}")
    print(
        json.dumps(
            {
                "architecture": architecture,
                "version": manifest["evidenceforge_version"],
                "runtime_checksum": "passed",
                "isolated_cli": "passed",
                "bundled_skills_and_references": "passed",
                "validation": "passed",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

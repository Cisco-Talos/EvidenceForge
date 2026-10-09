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


def run_cli(
    cli: Path,
    arguments: list[str],
    workspace: Path,
    environment: dict[str, str],
    *,
    timeout: int = 30,
    expected_exit_code: int = 0,
) -> str:
    """Run the standalone CLI without development dependencies or Studio state."""
    result = subprocess.run(
        [str(cli), *arguments],
        cwd=workspace,
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != expected_exit_code:
        raise RuntimeError(f"Packaged CLI failed: {arguments}\n{result.stderr}\n{result.stdout}")
    return result.stdout


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
            ["version"],
            ["schema", "environment", "--json"],
            ["pack", "list", "--json"],
            ["install-skills", "--agent", "chatgpt"],
        ]
        for command in commands:
            run_cli(cli, command, workspace, environment)
        assert any((workspace / ".agents/skills").rglob("SKILL.md"))
        assert any((workspace / ".agents/skills").rglob("scenario-core.md"))
        for skill in ("scenario", "pack", "industry-pack", "organization-pack"):
            installed = workspace / f".agents/skills/eforge-{skill}/SKILL.md"
            assert "display_name" in installed.read_text(encoding="utf-8")
        lifecycle_reference = next(
            (workspace / ".agents/skills").rglob("artifact-lifecycle.md")
        ).read_text(encoding="utf-8")
        assert "--display-name" in lifecycle_reference and "--clear" in lifecycle_reference
        assert (
            "--expected-digest" in lifecycle_reference and "scenario rename" in lifecycle_reference
        )
        assert "configured project-over-user publisher" in lifecycle_reference
        assert "pack inspect-artifact" in lifecycle_reference
        pack_archive = workspace / "received.efpack"
        built = json.loads(
            run_cli(
                cli,
                [
                    "pack",
                    "build",
                    "package:evidenceforge:organization:metrolink-specialty-care@1.0.0",
                    "--output",
                    str(pack_archive),
                    "--json",
                ],
                workspace,
                environment,
            )
        )
        inspected = json.loads(
            run_cli(cli, ["pack", "inspect", str(pack_archive), "--json"], workspace, environment)
        )
        assert inspected == {"valid": True, "root": built["root"], "members": built["members"]}
        invalid_archive = workspace / "invalid.efpack"
        invalid_archive.write_bytes(b"not a ZIP archive")
        invalid = json.loads(
            run_cli(
                cli,
                ["pack", "inspect", str(invalid_archive), "--json"],
                workspace,
                environment,
                expected_exit_code=2,
            )
        )
        assert set(invalid) == {"valid", "error"} and invalid["valid"] is False
        run_cli(
            cli,
            [
                "pack",
                "publisher",
                "set",
                "native-testing",
                "--display-name",
                "Native Tests",
                "--scope",
                "project",
            ],
            workspace,
            environment,
        )
        for selector in ("scenario.envelope", "pack.envelope"):
            payload = json.loads(
                run_cli(cli, ["schema", selector, "--json"], workspace, environment)
            )
            assert "display_name" in payload["fields"]
        for group, kind, name in (
            ("scenario", "scenario", "_native" + "A" * 300),
            ("pack", "industry", "native-industry-" + "a" * 300),
            ("pack", "organization", "native-organization-" + "a" * 300),
        ):
            inspect_command = "inspect-artifact" if group == "pack" else "inspect"
            draft = json.loads(
                run_cli(
                    cli,
                    [
                        group,
                        "new-draft",
                        name,
                        "--kind",
                        kind,
                        "--display-name",
                        "Friendly Native Title — Équipe",
                        "--json",
                    ],
                    workspace,
                    environment,
                )
            )["path"]
            inspected = json.loads(
                run_cli(cli, [group, inspect_command, draft, "--json"], workspace, environment)
            )
            assert inspected["name"] == name
            assert inspected["display_name"] == "Friendly Native Title — Équipe"
            assert inspected["lifecycle"]["publisher"] == "native-testing"
            assert "version" not in inspected["lifecycle"]
            edited = json.loads(
                run_cli(
                    cli,
                    [group, "display-name", draft, "--value", "Edited Native Title", "--json"],
                    workspace,
                    environment,
                )
            )
            assert edited["name"] == name and edited["display_name"] == "Edited Native Title"
            cleared = json.loads(
                run_cli(
                    cli, [group, "display-name", draft, "--clear", "--json"], workspace, environment
                )
            )
            assert cleared["name"] == name and cleared["display_name"] is None
            renamed = json.loads(
                run_cli(
                    cli,
                    [
                        group,
                        "rename",
                        draft,
                        f"renamed-{kind}",
                        "--expected-digest",
                        cleared["digest"],
                        "--json",
                    ],
                    workspace,
                    environment,
                )
            )
            assert renamed["path"] == draft
            checked = json.loads(
                run_cli(cli, [group, inspect_command, draft, "--json"], workspace, environment)
            )
            assert checked["name"] == f"renamed-{kind}" and checked["display_name"] is None
            assert checked["lifecycle"]["draft_id"] == cleared["lifecycle"]["draft_id"]
            properties = json.loads(
                run_cli(cli, [group, "properties", draft, "--json"], workspace, environment)
            )
            changes = workspace / "properties.json"
            changes.write_text(
                json.dumps(
                    {"display_name": "Native Properties Title", "release_notes": "Native notes"}
                )
            )
            run_cli(
                cli,
                [
                    group,
                    "edit-properties",
                    draft,
                    "--changes",
                    str(changes),
                    "--expected-digest",
                    properties["digest"],
                    "--json",
                ],
                workspace,
                environment,
            )
            properties = json.loads(
                run_cli(cli, [group, "properties", draft, "--json"], workspace, environment)
            )
            assert properties["display_name"] == "Native Properties Title"
            assert properties["lifecycle"]["release_notes"] == "Native notes"
        fixture = Path(__file__).resolve().parents[1] / "tests/fixtures/scenarios/minimal.yaml"
        scenario = workspace / "scenario.yaml"
        shutil.copyfile(fixture, scenario)
        run_cli(
            cli,
            ["validate", str(scenario), "--json"],
            workspace,
            environment,
            timeout=60,
        )
        upgraded = json.loads(
            run_cli(cli, ["scenario", "upgrade", str(scenario), "--json"], workspace, environment)
        )["path"]
        assert (
            json.loads(
                run_cli(cli, ["scenario", "inspect", upgraded, "--json"], workspace, environment)
            )["lifecycle"]["publisher"]
            == "native-testing"
        )
        assert scenario.read_bytes() == fixture.read_bytes()
        run_cli(
            cli,
            ["scenario", "display-name", upgraded, "--value", "Native Generation Title", "--json"],
            workspace,
            environment,
        )
        run_cli(cli, ["scenario", "check", upgraded, "--json"], workspace, environment)
        output = workspace / "generated"
        run_cli(
            cli,
            [
                "generate",
                upgraded,
                "--output",
                str(output),
                "--seed",
                "42",
                "--checkpoint-hours",
                "1",
            ],
            workspace,
            environment,
            timeout=120,
        )
        assert (output / "RESOLVED_SCENARIO.yaml").is_file()
        assert any(
            path.is_file() and path.stat().st_size > 0 for path in (output / "data").rglob("*")
        )
        assert not (output / ".eforge-generation").exists()
        bundle = json.loads(
            run_cli(
                cli,
                ["scenario", "bundle-properties", str(output), "--json"],
                workspace,
                environment,
            )
        )
        assert bundle["complete"] and bundle["data_bytes"] > 0 and bundle["formats"]
        assert bundle["size_bytes"] >= bundle["data_bytes"]
        properties = json.loads(
            run_cli(cli, ["scenario", "properties", upgraded, "--json"], workspace, environment)
        )
        assert (
            properties["validated_with"]["evidenceforge_version"]
            == manifest["evidenceforge_version"]
        )
    print(
        json.dumps(
            {
                "architecture": architecture,
                "version": manifest["evidenceforge_version"],
                "runtime_checksum": "passed",
                "isolated_cli": "passed",
                "bundled_skills_and_references": "passed",
                "pack_inspection": "passed",
                "artifact_naming": "passed",
                "artifact_properties": "passed",
                "bundle_data_properties": "passed",
                "validation": "passed",
                "checkpoint_enabled_generation": "passed",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

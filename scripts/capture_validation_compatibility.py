# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Capture CLI/configuration compatibility in either revision's isolated interpreter.

Run once per revision with distinct --output directories, using the same fixture repository.
The capture is diagnostic; compare package validation documents/digests separately from user data.
"""

import argparse
import json
import os
import shutil
from pathlib import Path
from typing import Any

import yaml
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.composition import compile_scenario


def main() -> None:
    """Capture both scenario versions, project scopes, and immutable pack operations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(exist_ok=False)
    repo = args.repository.resolve()
    runner = CliRunner()
    rows: dict[str, Any] = {}

    def call(key: str, args: list[str], cwd: Path | None = None) -> Any:
        os.chdir(cwd or root)
        r = runner.invoke(app, args)
        payload = None
        try:
            payload = json.loads(r.stdout)
        except ValueError:
            pass
        rows[key] = {
            "exit": r.exit_code,
            "stdout": r.stdout,
            "stderr": r.stderr,
            "payload": payload,
        }
        (root / "results.json").write_text(json.dumps(rows, indent=2, default=str))
        return r

    for p in ("a", "b"):
        project = root / p
        project.mkdir()
        child = project / "child"
        child.mkdir()
        overlay = project / ".eforge/config/activity"
        overlay.mkdir(parents=True)
        (overlay / "dns_registry.yaml").write_text(
            yaml.safe_dump(
                {
                    "domains": [
                        {
                            "domain": "claims.healthcare.example",
                            "ips": ["203.0.113." + ("44" if p == "a" else "45")],
                            "tags": ["healthcare"],
                            "_replace": True,
                        }
                    ]
                }
            )
        )
        for version, fixture in [("v1", "minimal.yaml"), ("v2", "northstar-health-pack.yaml")]:
            scenario = project / (version + ".yaml")
            shutil.copyfile(repo / "tests/fixtures/scenarios" / fixture, scenario)
            for mode, cwd, extra in [
                ("cwd", project, []),
                ("explicit", child, ["--project-root", str(project)]),
                ("no_ancestor", child, []),
            ]:
                prefix = p + "-" + version + "-" + mode
                call(prefix + "-validate", ["validate", str(scenario), *extra], cwd)
                call(
                    prefix + "-resolve",
                    [
                        "resolve",
                        str(scenario),
                        "--output",
                        str(project / (prefix + "-resolved.yaml")),
                        "--json",
                        *extra,
                    ],
                    cwd,
                )
                compiled = compile_scenario(scenario, project_root=project if extra else None)
                rows[prefix + "-compiled"] = {"payload": compiled.model_dump(mode="json")}
            call(
                p + "-" + version + "-resolved-validate",
                ["validate", str(project / (p + "-" + version + "-cwd-resolved.yaml"))],
                project,
            )
        call(p + "-config", ["validate-config", "--json"], project)
        call(
            p + "-config-explicit",
            ["validate-config", "--json", "--project-root", str(project)],
            child,
        )
        call(p + "-config-no-ancestor", ["validate-config", "--json"], child)
    # Reenter A after B in one interpreter to detect stale configuration.
    call("a-config-repeat", ["validate-config", "--json"], root / "a")
    ref = "package:evidenceforge:organization:metrolink-specialty-care@1.0.0"
    archive = root / "pack.efpack"
    for key, args in [
        ("pack-validate", ["pack", "validate", ref, "--json"]),
        ("pack-build", ["pack", "build", ref, "--output", str(archive), "--json"]),
        ("pack-inspect", ["pack", "inspect", str(archive), "--json"]),
        (
            "pack-import",
            [
                "pack",
                "import",
                str(archive),
                "--scope",
                "project",
                "--accept-publisher",
                "evidenceforge",
                "--project-root",
                str(root / "a"),
                "--json",
            ],
        ),
        (
            "pack-hydrate",
            [
                "pack",
                "hydrate",
                "evidenceforge:organization:metrolink-specialty-care@1.0.0",
                "--scope",
                "project",
                "--project-root",
                str(root / "a"),
                "--json",
            ],
        ),
    ]:
        call(key, args)
    for fmt in ("text", "json"):
        call(
            "legacy-eval-" + fmt,
            [
                "eval",
                str(repo / "tests/fixtures/eval/good"),
                "--scenario",
                str(repo / "tests/fixtures/scenarios/retail-store-ftp-attack.yaml"),
                "--format",
                fmt,
            ],
        )
    rows["installed-locks"] = {
        "payload": {str(p.relative_to(root)): p.read_text() for p in root.rglob("pack.lock.yaml")}
    }
    (root / "results.json").write_text(json.dumps(rows, indent=2, default=str))
    print({k: v.get("exit") for k, v in rows.items() if v.get("exit")})


if __name__ == "__main__":
    main()

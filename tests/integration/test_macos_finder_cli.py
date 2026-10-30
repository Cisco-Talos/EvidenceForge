# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A Finder app's native exec survives public generation and output filtering."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from evidenceforge.config import get_activity_directory
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from tests.unit.test_macos_installed_provisioning import _scenario

_APP = "/Applications/EForgeReference.app/Contents/MacOS/EForgeReference"


@pytest.mark.slow
def test_finder_cli_has_one_authored_exec_and_filter_independent_native_bytes(
    tmp_path: Path,
) -> None:
    # Explicit test-only opt-in; other machine binaries stay deployed for their owners.
    catalog = yaml.safe_load((get_activity_directory() / "application_catalog.yaml").read_text())
    selected = {
        "schema_version": 2,
        "default_deployment": catalog["default_deployment"],
        "applications": [
            {
                "id": application["id"],
                "personas": ["developer"] if application["id"] == "macos-reference-app" else [],
                "_replace": True,
            }
            for application in catalog["applications"]
            if "macos" in application["platforms"]
        ],
    }
    overlay = tmp_path / ".eforge/config/activity/application_catalog.yaml"
    overlay.parent.mkdir(parents=True)
    overlay.write_text(yaml.safe_dump(selected, sort_keys=False))
    raw = _scenario().model_dump(mode="json", exclude_none=True)
    raw["macos_process_coverage"] = "partial"  # In-window GUI/terminal startup remains separate.
    raw["environment"]["systems"] = raw["environment"]["systems"][:1]
    raw["environment"]["users"] = raw["environment"]["users"][:1]
    raw["environment"]["network"]["segments"][0]["systems"] = ["MAC-01"]
    raw["output"]["logs"] = [{"format": "ecar"}, {"format": "macos_endpoint_security"}]
    raw["storyline"] = [
        {
            "id": "finder-reference",
            "time": "+30m",
            "actor": "alex",
            "system": "MAC-01",
            "activity": "Launch an invented regular reference app from Finder",
            "events": [
                {
                    "type": "process",
                    "process_name": _APP,
                    "launch_method": "finder",
                    "supplementary": "none",
                }
            ],
        }
    ]
    scenario = tmp_path / "invented-finder.yaml"
    scenario.write_text(yaml.safe_dump(raw, sort_keys=False))
    snapshots = []
    for label, seed, formats in (("full", "19", ""), ("native", "83", "macos_endpoint_security")):
        output = tmp_path / label
        arguments = [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario),
            "--output",
            str(output),
            "--seed",
            "349",
            "--checkpoint-hours",
            "0",
            "--project-root",
            str(tmp_path),
        ]
        if formats:
            arguments.extend(["--formats", formats])
        result = subprocess.run(
            arguments,
            env=os.environ | {"PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        paths = list((output / "data").rglob("macos_endpoint_security.ndjson"))
        snapshots.append({str(path.relative_to(output)): path.read_bytes() for path in paths})
        app_execs = [
            record
            for path in paths
            for line in path.read_text().splitlines()
            if (record := decode_endpoint_security_record(line)).event_type == 9
            and record.event.exec.target.executable.path == _APP
        ]
        assert app_execs
        truth = json.loads((output / "GROUND_TRUTH.json").read_text())
        authored = next(
            event for event in truth["events"] if event["storyline_id"] == "finder-reference"
        )
        assert authored["attributes"]["native_process_model"] == "gui_exec"
        assert (
            sum(
                record.event.exec.target.audit_token.pid == authored["attributes"]["pid"]
                for record in app_execs
            )
            == 1
        )
        assert app_execs[0].process.executable.path == "/usr/libexec/xpcproxy"
        assert (
            app_execs[0].process.audit_token.pid == app_execs[0].event.exec.target.audit_token.pid
        )
        launcher_execs = [
            record
            for path in paths
            for line in path.read_text().splitlines()
            if (record := decode_endpoint_security_record(line)).event_type == 9
            and record.event.exec.target.audit_token.pid == authored["attributes"]["pid"]
            and record.event.exec.target.executable.path == "/usr/libexec/xpcproxy"
        ]
        assert (
            len(launcher_execs) == 1
            and launcher_execs[0].process.executable.path == "/sbin/launchd"
        )
        assert launcher_execs[0].event.exec.target.audit_token.euid == 0
        fork_records = [
            record
            for path in paths
            for line in path.read_text().splitlines()
            if (record := decode_endpoint_security_record(line)).event_type == 11
            and record.event.fork.child.audit_token.pid == authored["attributes"]["pid"]
        ]
        assert len(fork_records) == 1
        assert fork_records[0].process.audit_token.asid > 0
        assert fork_records[0].process.parent_audit_token.asid == 0
    assert snapshots[0] == snapshots[1]


@pytest.mark.slow
def test_finder_checkpoint_resume_retains_both_executions_and_gui_credentials(
    tmp_path: Path,
    scenarios_dir: Path,
) -> None:
    from tests.integration.test_checkpoint_smoke import (
        test_short_generation_checkpoint_suspension_and_resume as checkpoint_gate,
    )

    checkpoint_gate(
        tmp_path, scenarios_dir, "default", None, True, None, False, False, False, finder=True
    )

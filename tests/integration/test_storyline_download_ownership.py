"""A downloaded executable must not acquire a second, child-owned creation."""

import json
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario


@pytest.mark.slow
def test_download_creation_stays_owned_by_downloader(tmp_path: Path) -> None:
    scenario = Scenario.model_validate(
        {
            "version": "1.0",
            "name": "download-ownership-regression",
            "description": "Process artifact ownership regression",
            "generation_seed": 20261102,
            "environment": {
                "description": "One Linux test host",
                "users": [
                    {
                        "username": "alex",
                        "full_name": "Alex Example",
                        "email": "alex@example.test",
                        "primary_system": "APP",
                    }
                ],
                "systems": [
                    {"hostname": "APP", "ip": "10.88.0.20", "os": "Ubuntu 22.04", "type": "server"}
                ],
            },
            "time_window": {"start": "2026-10-20T10:00:00Z", "duration": "10m", "warmup": "1h"},
            "baseline_activity": {
                "description": "Low-volume fixture",
                "intensity": "low",
                "variation": "low",
            },
            "storyline": [
                {
                    "id": "download",
                    "time": "+2m",
                    "actor": "alex",
                    "system": "APP",
                    "activity": "Download file",
                    "events": [
                        {
                            "type": "process",
                            "process_name": "/usr/bin/curl",
                            "command_line": "curl -fsS -o /tmp/cache-sync https://cdn.example.test/cache-sync",
                        }
                    ],
                },
                {
                    "id": "execute",
                    "time": "+4m",
                    "actor": "alex",
                    "system": "APP",
                    "activity": "Run existing file",
                    "events": [
                        {
                            "type": "process",
                            "process_name": "/tmp/cache-sync",
                            "command_line": "/tmp/cache-sync --version",
                        }
                    ],
                },
            ],
            "output": {"logs": [{"format": "ecar"}], "destination": str(tmp_path)},
        }
    )
    GenerationEngine(scenario, tmp_path).generate()
    rows: list[dict[str, Any]] = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
        if line
    ]
    births = {
        r["objectID"]: r for r in rows if r["object"] == "PROCESS" and r["action"] == "CREATE"
    }
    creates = [
        r
        for r in rows
        if r["object"] == "FILE"
        and r["action"] == "CREATE"
        and r["properties"].get("file_path") == "/tmp/cache-sync"
    ]
    assert len(creates) == 1
    assert births[creates[0]["actorID"]]["properties"]["image_path"] == "/usr/bin/curl"
    executions = [r for r in births.values() if r["properties"]["image_path"] == "/tmp/cache-sync"]
    assert len(executions) == 1
    assert creates[0]["timestamp_ms"] < executions[0]["timestamp_ms"]
    assert creates[0]["actorID"] != executions[0]["objectID"]

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Native SMB observations consume policy repository paths without renderer rewrites."""

import json
import xml.etree.ElementTree as ET
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario, SmbActivityEventSpec, SmbShareLocation
from evidenceforge.utils.rng import generation_seed_scope, reset_thread_rng
from tests.integration.test_storage_policy_repository import policy_scenario


@pytest.mark.slow
@pytest.mark.parametrize("role", ["sysvol", "netlogon"])
def test_native_policy_read_uses_one_compiled_path_across_sources(
    scenarios_dir: Path, tmp_path: Path, role: str
) -> None:
    data = policy_scenario(scenarios_dir).model_dump()
    data["output"]["logs"] = [{"format": name} for name in ("windows", "ecar", "zeek")]
    data["environment"]["storage"]["servers"] = [
        {"system": "DC-1", "presets": ["dc_policy"], "audit": "high"}
    ]
    scenario = Scenario.model_validate(data)
    with generation_seed_scope(scenario.generation_seed):
        reset_thread_rng()
        engine = GenerationEngine(scenario, tmp_path)
        try:
            engine._initialize()
            generator = engine.activity_generator
            actor, client = scenario.environment.users[0], scenario.environment.systems[0]
            generator.generate_logon(actor, client, engine.start_time + timedelta(minutes=1))
            share = generator._storage_world.share(f"DC-1.{role}")
            selected = next(
                file
                for file in share.files
                if role == "netlogon" or file.path.endswith("\\GPT.INI")
            )
            spec = SmbActivityEventSpec(
                type="smb_activity",
                operation="read",
                target=SmbShareLocation(share=share.ref, path=selected.path),
            )
            result = generator.generate_smb_activity(
                spec=spec,
                actor=actor,
                parent_system=client,
                time=engine.start_time + timedelta(minutes=10),
                activity_source="storyline",
            )
            assert result.transport_uids
        finally:
            engine._close_emitters()
    security = next(
        path
        for path in tmp_path.rglob("windows_event_security.xml")
        if path.parent.name.startswith("DC-1")
    )
    native: dict[str, list[dict[str, str]]] = {}
    for event in ET.parse(security).getroot():
        eid = event.findtext("{*}System/{*}EventID")
        fields = {
            node.attrib["Name"]: node.text or "" for node in event.findall("{*}EventData/{*}Data")
        }
        native.setdefault(eid, []).append(fields)
    assert any(row.get("RelativeTargetName") == selected.path for row in native["5145"])
    assert any(
        share.root.casefold() in row.get("ShareLocalPath", "").casefold() for row in native["5140"]
    )
    actions = [
        json.loads(line)
        for path in tmp_path.rglob("smb_files.json")
        for line in path.read_text().splitlines()
    ]
    assert any(str(row.get("name", "")).endswith(selected.path) for row in actions)
    files = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    assert any(
        row.get("object") == "FILE"
        and selected.path in row.get("properties", {}).get("file_path", "")
        for row in files
    )

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Native SMB NTLM evidence follows the authoritative credential-validation path."""

import xml.etree.ElementTree as ET
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario, SmbActivityEventSpec, SmbShareLocation
from evidenceforge.utils.rng import generation_seed_scope, reset_thread_rng
from tests.integration.test_storage_policy_repository import policy_scenario


@pytest.mark.slow
@pytest.mark.parametrize("fault_mode", ["none", "member_lost_return", "publication_lost_return"])
@pytest.mark.parametrize("server_kind", ["domain_controller", "windows_member", "samba_member"])
def test_domain_ntlm_smb_has_authoritative_validation_and_mechanism_guid(
    scenarios_dir: Path,
    tmp_path: Path,
    server_kind: str,
    fault_mode: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = policy_scenario(scenarios_dir).model_dump()
    data["output"]["logs"] = [{"format": name} for name in ("windows", "ecar", "zeek", "syslog")]
    if server_kind != "domain_controller":
        server = next(
            system for system in data["environment"]["systems"] if system["hostname"] == "DC-2"
        )
        server.update(
            type="server",
            roles=["file_server"],
            services=["samba", "smbd"] if server_kind == "samba_member" else ["smb"],
            os="Ubuntu Server 24.04" if server_kind == "samba_member" else "Windows Server 2022",
        )
    scenario = Scenario.model_validate(data)
    with generation_seed_scope(scenario.generation_seed):
        reset_thread_rng()
        engine = GenerationEngine(scenario, tmp_path)
        try:
            engine._initialize()
            generator = engine.activity_generator
            actor, client = scenario.environment.users[0], scenario.environment.systems[0]
            generator.generate_logon(
                actor, client, engine.start_time + timedelta(minutes=1), logon_type=2
            )
            ref = "DC-1.sysvol" if server_kind == "domain_controller" else "DC-2.collaboration"
            share = generator._storage_world.share(ref)
            spec = SmbActivityEventSpec(
                type="smb_activity",
                operation="read",
                auth_protocol="ntlmssp",
                target=SmbShareLocation(share=share.ref, path=share.files[0].path),
            )
            if fault_mode != "none" and server_kind != "samba_member":
                from tests.unit.test_smb_persistent_production import _OneShotPublicFault

                method = (
                    "commit_persistent_smb_projection_member"
                    if fault_mode == "member_lost_return"
                    else "publish_persistent_smb_source_publication"
                )
                fault = _OneShotPublicFault(getattr(generator.dispatcher, method), "lost_return")
                monkeypatch.setattr(generator.dispatcher, method, fault)
            result = generator.generate_smb_activity(
                spec=spec,
                actor=actor,
                parent_system=client,
                time=engine.start_time + timedelta(minutes=10),
                activity_source="storyline",
            )
            assert result.transport_uids
            if fault_mode != "none" and server_kind != "samba_member":
                assert fault.calls >= 2
        finally:
            engine._close_emitters()
    validations = []
    logons = []
    for path in tmp_path.rglob("windows_event_security.xml"):
        for event in ET.parse(path).getroot():
            eid = event.findtext("{*}System/{*}EventID")
            fields = {
                node.attrib["Name"]: node.text or ""
                for node in event.findall("{*}EventData/{*}Data")
            }
            if (
                eid == "4776"
                and fields.get("TargetUserName") == actor.username
                and fields.get("Workstation") == client.hostname
                and int(fields.get("Status", "0x1"), 16) == 0
            ):
                validations.append((path.parent.name, fields))
            if (
                eid == "4624"
                and path.parent.name.startswith(share.system)
                and fields.get("TargetUserName") == actor.username
                and fields.get("LogonType") == "3"
            ):
                logons.append(fields)
    assert len(validations) == 1
    assert validations[0][0].startswith("DC-1")
    if server_kind != "samba_member":
        assert len(logons) == 1 and logons[0]["AuthenticationPackageName"] == "NTLM"
        assert logons[0]["LogonGuid"] == "{00000000-0000-0000-0000-000000000000}"

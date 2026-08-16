# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Integration coverage for canonical SMB activity and the TCP/445 cutover."""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from evidenceforge.composition import compile_scenario
from evidenceforge.composition.packs import PackRepository
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.resource_forecast import (
    ForecastRange,
    ResourceForecast,
    ResourceSnapshot,
)
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils import load_yaml, write_yaml


def _base_scenario(scenarios_dir: Path) -> dict:
    data = load_yaml(scenarios_dir / "minimal.yaml")
    data["time_window"] = {"start": "2024-01-15T10:00:00Z", "duration": "20m"}
    data["baseline_activity"]["intensity"] = "low"
    data["baseline_activity"]["traffic_rates"] = {"smb_interval": 50000}
    data["environment"]["systems"].append(
        {
            "hostname": "FS-01",
            "ip": "10.0.0.20",
            "os": "Windows Server 2022",
            "type": "server",
            "roles": ["file_server"],
        }
    )
    data["environment"]["network"]["segments"][0]["systems"].append("FS-01")
    data["environment"]["storage"] = {
        "population": "small",
        "servers": [
            {
                "system": "FS-01",
                "presets": [],
                "volumes": [{"id": "data", "mount": "D:\\"}],
                "shares": [
                    {
                        "id": "finance",
                        "name": "Finance",
                        "volume": "data",
                        "root": "Departments\\Finance",
                        "preset": "department",
                        "seed_files": [
                            {
                                "ref": "forecast",
                                "path": "Reports\\FY26\\forecast.xlsx",
                                "size_bytes": 1843200,
                                "tags": ["finance"],
                            }
                        ],
                    }
                ],
            }
        ],
    }
    data["output"]["logs"] = [
        {"format": "windows"},
        {"format": "zeek"},
        {"format": "ecar"},
    ]
    return data


def _json_records(output: Path, filename: str) -> list[dict]:
    records: list[dict] = []
    for path in output.rglob(filename):
        records.extend(
            json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line
        )
    return records


def _security_events(output: Path, hostname: str) -> list[tuple[int, str, dict[str, str]]]:
    path = next(output.rglob(f"{hostname}*/windows_event_security.xml"))
    events: list[tuple[int, str, dict[str, str]]] = []
    for event in ET.parse(path).getroot():
        system = event.find("{*}System")
        event_data = event.find("{*}EventData")
        assert system is not None and event_data is not None
        event_id = int(system.find("{*}EventID").text or "0")
        timestamp = system.find("{*}TimeCreated").attrib["SystemTime"]
        fields = {item.attrib["Name"]: item.text or "" for item in event_data}
        events.append((event_id, timestamp, fields))
    return events


def _forecast(output: Path) -> ResourceForecast:
    available = 64 * 1024**3
    return ResourceForecast(
        calibration_version=1,
        calibration_label="test",
        memory=ForecastRange(lower_bytes=1, expected_bytes=1, upper_bytes=1),
        final_output=ForecastRange(lower_bytes=1, expected_bytes=1, upper_bytes=1),
        disk=ForecastRange(lower_bytes=1, expected_bytes=1, upper_bytes=1),
        snapshot=ResourceSnapshot(
            total_memory_bytes=available,
            available_memory_bytes=available,
            free_swap_bytes=available,
            free_disk_bytes=available,
            disk_path=str(output),
        ),
    )


def test_semantic_smb_read_projects_correlated_sparse_evidence(
    scenarios_dir: Path,
    tmp_path: Path,
) -> None:
    data = _base_scenario(scenarios_dir)
    data["storyline"] = [
        {
            "id": "read-forecast",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Read a forecast from Finance",
            "events": [
                {
                    "type": "smb_activity",
                    "operation": "read",
                    "target": {
                        "type": "share",
                        "share": "FS-01.finance",
                        "file_ref": "forecast",
                    },
                    "outcome": "success",
                }
            ],
        }
    ]

    GenerationEngine(Scenario(**data), tmp_path, resource_forecast=_forecast(tmp_path)).generate()

    mappings = _json_records(tmp_path, "smb_mapping.json")
    actions = _json_records(tmp_path, "smb_files.json")
    files = _json_records(tmp_path, "files.json")
    semantic_actions = [
        record for record in actions if str(record.get("name", "")).endswith("forecast.xlsx")
    ]
    semantic_files = [
        record for record in files if str(record.get("filename", "")).endswith("forecast.xlsx")
    ]
    connections = _json_records(tmp_path, "conn.json")
    ground_truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text(encoding="utf-8"))
    manifest = json.loads((tmp_path / "STORAGE_MANIFEST.json").read_text(encoding="utf-8"))

    assert any(record["service"] == "Finance" for record in mappings)
    assert [record["action"] for record in semantic_actions] == [
        "SMB::FILE_OPEN",
        "SMB::FILE_READ",
    ]
    assert len(semantic_files) == 1
    assert semantic_files[0]["is_orig"] is False
    assert semantic_files[0]["total_bytes"] == 1843200
    assert semantic_files[0]["fuid"].startswith("F")
    connection = next(
        record for record in connections if record["uid"] == semantic_actions[0]["uid"]
    )
    connection_end = connection["ts"] + connection["duration"]
    assert all(connection["ts"] <= record["ts"] <= connection_end for record in semantic_actions)
    assert semantic_files[0]["ts"] + semantic_files[0]["duration"] <= connection_end
    ecar_flows = [
        record
        for record in _json_records(tmp_path, "ecar.json")
        if record.get("object") == "FLOW"
        and record.get("properties", {}).get("src_ip") == connection["id.orig_h"]
        and int(record.get("properties", {}).get("src_port", 0)) == connection["id.orig_p"]
        and record.get("properties", {}).get("dst_ip") == connection["id.resp_h"]
        and int(record.get("properties", {}).get("dst_port", 0)) == connection["id.resp_p"]
    ]
    assert ecar_flows
    assert all(record["timestamp_ms"] / 1000 < connection_end for record in ecar_flows)
    assert semantic_files[0]["seen_bytes"] <= connection["resp_bytes"]
    smb_truth = next(event for event in ground_truth["events"] if event["kind"] == "smb_activity")
    assert smb_truth["attributes"]["operations"][0]["path"] == ("Reports\\FY26\\forecast.xlsx")
    assert smb_truth["attributes"]["transport_uids"][0] in {record["uid"] for record in connections}
    assert any(share["ref"] == "FS-01.finance" for share in manifest["shares"])


def test_organization_pack_tiny_storage_vocabulary_generates_with_auto_population(
    tmp_path: Path,
) -> None:
    pack_root = PackRepository(tmp_path).create_skeleton(
        "organization",
        "tiny-storage-org",
        "1.0.0",
    )
    write_yaml(
        {
            "storage_catalog": {
                "records": {
                    "description": "One intentionally tiny reusable record vocabulary.",
                    "data": {
                        "directories": ["Records"],
                        "subjects": ["Case"],
                        "files": [
                            {
                                "extension": ".pdf",
                                "mime": "application/pdf",
                                "weight": 1,
                            }
                        ],
                    },
                }
            }
        },
        pack_root / "catalogs/storage_catalog.yaml",
    )
    write_yaml(
        {
            "environment": {
                "description": "Fictional organization with a compact record library.",
                "timezone": {"default": "UTC"},
                "domain": "tiny-storage.example",
                "users": [
                    {
                        "username": "casey.lee",
                        "full_name": "Casey Lee",
                        "email": "casey.lee@tiny-storage.example",
                        "primary_system": "TINY-WS-01",
                    }
                ],
                "systems": [
                    {
                        "hostname": "TINY-WS-01",
                        "ip": "10.88.10.21",
                        "os": "Windows 11",
                        "type": "workstation",
                        "assigned_user": "casey.lee",
                        "roles": ["workstation"],
                    },
                    {
                        "hostname": "TINY-FILE-01",
                        "ip": "10.88.20.20",
                        "os": "Windows Server 2022",
                        "type": "server",
                        "services": ["SMB"],
                        "roles": ["file_server"],
                    },
                ],
                "storage": {
                    "servers": [
                        {
                            "system": "TINY-FILE-01",
                            "presets": [],
                            "volumes": [{"id": "data", "mount": "D:\\"}],
                            "shares": [
                                {
                                    "id": "records",
                                    "name": "Records",
                                    "volume": "data",
                                    "preset": "records",
                                }
                            ],
                        }
                    ]
                },
            }
        },
        pack_root / "model/environment.yaml",
    )
    write_yaml(
        {
            "baseline_activity": {
                "description": "Low-volume background activity.",
                "intensity": "low",
                "variation": "medium",
                "suspicious_noise": "low",
                "traffic_rates": {"smb_interval": 50000},
            }
        },
        pack_root / "model/baseline_activity.yaml",
    )
    scenario_path = tmp_path / "scenario.yaml"
    write_yaml(
        {
            "scenario_version": "2.0",
            "composition": {
                "organization": {
                    "source": "project",
                    "name": "tiny-storage-org",
                    "version": "1.0.0",
                }
            },
            "name": "tiny-storage-organization-regression",
            "description": "Read from a storage vocabulary smaller than auto population.",
            "time_window": {
                "start": "2026-08-17T10:00:00Z",
                "duration": "20m",
            },
            "storyline": [
                {
                    "id": "read-record",
                    "time": "+10m",
                    "actor": "casey.lee",
                    "system": "TINY-WS-01",
                    "activity": "Read one organization record.",
                    "events": [
                        {
                            "type": "smb_activity",
                            "operation": "read",
                            "target": {
                                "type": "share",
                                "share": "TINY-FILE-01.records",
                            },
                            "outcome": "success",
                        }
                    ],
                }
            ],
            "output": {
                "logs": [{"format": "windows"}, {"format": "ecar"}],
                "destination": "./output",
                "compression": False,
            },
        },
        scenario_path,
    )

    compiled = compile_scenario(scenario_path, project_root=tmp_path)
    output = tmp_path / "generated"
    GenerationEngine(
        compiled.scenario,
        output,
        resource_forecast=_forecast(output),
        compiled_scenario=compiled,
        scenario_root=tmp_path,
    ).generate()

    manifest = json.loads((output / "STORAGE_MANIFEST.json").read_text(encoding="utf-8"))
    share = next(item for item in manifest["shares"] if item["ref"] == "TINY-FILE-01.records")
    assert share["preset"] == "tiny-storage-org:records"
    assert share["file_count"] == 36
    assert share["population_resolution"] == {
        "requested_file_count": 64,
        "effective_file_count": 36,
        "realizable_file_count": 36,
        "capped": True,
    }
    assert manifest["resolved_storyline_targets"][0]["operations"][0]["path"]


def test_high_audit_smb_lifecycle_uses_native_fields_and_ordering(
    scenarios_dir: Path,
    tmp_path: Path,
) -> None:
    data = _base_scenario(scenarios_dir)
    data["environment"]["storage"]["servers"][0]["audit"] = "high"
    data["environment"]["storage"]["servers"][0]["shares"][0]["access"] = {"modify": ["test_user"]}
    data["storyline"] = [
        {
            "id": "update-forecast",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Update a forecast with high object auditing",
            "events": [
                {
                    "type": "smb_activity",
                    "operation": "update",
                    "target": {
                        "type": "share",
                        "share": "FS-01.finance",
                        "file_ref": "forecast",
                    },
                    "outcome": "success",
                }
            ],
        }
    ]

    GenerationEngine(Scenario(**data), tmp_path, resource_forecast=_forecast(tmp_path)).generate()

    ground_truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text(encoding="utf-8"))
    smb_truth = next(event for event in ground_truth["events"] if event["kind"] == "smb_activity")
    operation = smb_truth["attributes"]["operations"][0]
    smb_write = next(
        record
        for record in _json_records(tmp_path, "smb_files.json")
        if record.get("action") == "SMB::FILE_WRITE"
        and str(record.get("name", "")).endswith("forecast.xlsx")
    )
    file_record = next(
        record
        for record in _json_records(tmp_path, "files.json")
        if record.get("fuid") == smb_write["fuid"]
    )
    assert operation["content_version"] == 2
    assert smb_write["size"] == operation["size_bytes"]
    assert file_record["total_bytes"] == operation["size_bytes"]
    assert smb_write["fuid"] == file_record["fuid"]
    write_connection = next(
        record
        for record in _json_records(tmp_path, "conn.json")
        if record["uid"] == smb_write["uid"]
    )
    assert file_record["ts"] + file_record["duration"] <= (
        write_connection["ts"] + write_connection["duration"]
    )

    events = _security_events(tmp_path, "FS-01")
    handle_open = next(
        event
        for event in events
        if event[0] == 4656 and event[2].get("ObjectName", "").endswith("forecast.xlsx")
    )
    logon_id = handle_open[2]["SubjectLogonId"]
    handle_id = handle_open[2]["HandleId"]
    related = [
        event
        for event in events
        if event[2].get("SubjectLogonId") == logon_id or event[2].get("TargetLogonId") == logon_id
    ]
    event_by_id = {event_id: (timestamp, fields) for event_id, timestamp, fields in related}

    assert {4624, 4634, 4656, 4658, 4663, 5140, 5145} <= set(event_by_id)
    assert event_by_id[4624][0] < event_by_id[5140][0] < event_by_id[5145][0]
    assert event_by_id[5145][0] <= event_by_id[4656][0] < event_by_id[4663][0]
    assert event_by_id[4663][0] < event_by_id[4658][0] < event_by_id[4634][0]
    assert event_by_id[4624][1]["TargetUserSid"] == handle_open[2]["SubjectUserSid"]
    assert event_by_id[5140][1]["ShareLocalPath"] == r"\??\D:\Departments\Finance"
    assert "RelativeTargetName" not in event_by_id[5140][1]
    assert "Status" not in event_by_id[5140][1]
    assert event_by_id[5145][1]["AccessReason"] == "-"
    assert "Status" not in event_by_id[5145][1]
    assert int(event_by_id[4656][1]["AccessMask"], 16) & 0x2
    assert "%%4417" in event_by_id[4656][1]["AccessList"]
    assert (
        int(event_by_id[4663][1]["AccessMask"], 16) & ~int(event_by_id[4656][1]["AccessMask"], 16)
        == 0
    )
    assert event_by_id[4658][1]["HandleId"] == handle_id
    assert set(event_by_id[4658][1]) == {
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "ObjectServer",
        "HandleId",
        "ProcessId",
        "ProcessName",
    }


def test_generic_successful_smb_connection_is_transport_only(
    scenarios_dir: Path,
    tmp_path: Path,
) -> None:
    data = _base_scenario(scenarios_dir)
    data["environment"]["storage"]["servers"][0]["shares"] = []
    data["storyline"] = [
        {
            "id": "opaque-smb",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Opaque SMB transport",
            "events": [
                {
                    "type": "connection",
                    "dst_ip": "10.0.0.20",
                    "dst_port": 445,
                    "service": "smb",
                    "orig_bytes": 100000,
                    "resp_bytes": 200000,
                }
            ],
        }
    ]

    GenerationEngine(Scenario(**data), tmp_path, resource_forecast=_forecast(tmp_path)).generate()

    connections = [
        record
        for record in _json_records(tmp_path, "conn.json")
        if record.get("id.resp_h") == "10.0.0.20" and record.get("id.resp_p") == 445
    ]
    assert connections
    assert _json_records(tmp_path, "smb_mapping.json") == []
    assert _json_records(tmp_path, "smb_files.json") == []
    assert not [
        record for record in _json_records(tmp_path, "files.json") if record.get("source") == "SMB"
    ]


def test_smb_copy_fans_out_required_client_file_effect(
    scenarios_dir: Path,
    tmp_path: Path,
) -> None:
    data = _base_scenario(scenarios_dir)
    data["storyline"] = [
        {
            "id": "copy-forecast",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Copy forecast into a local collection cache",
            "events": [
                {
                    "type": "smb_activity",
                    "operation": "copy",
                    "purpose": "collection",
                    "source": {
                        "type": "share",
                        "share": "FS-01.finance",
                        "file_ref": "forecast",
                    },
                    "destination": {"type": "client", "path": "C:\\ProgramData\\cache\\"},
                    "outcome": "success",
                }
            ],
        }
    ]

    GenerationEngine(Scenario(**data), tmp_path, resource_forecast=_forecast(tmp_path)).generate()

    ecar = _json_records(tmp_path, "ecar.json")
    client_creates = [
        record
        for record in ecar
        if record.get("hostname") == "TEST-01"
        and record.get("object") == "FILE"
        and record.get("action") == "CREATE"
        and record.get("properties", {}).get("file_path") == "C:\\ProgramData\\cache\\forecast.xlsx"
    ]
    server_reads = [
        record
        for record in ecar
        if record.get("hostname") == "FS-01"
        and record.get("action") == "READ"
        and str(record.get("properties", {}).get("file_path", "")).endswith("forecast.xlsx")
    ]

    assert len(client_creates) == 1, ecar
    assert len(server_reads) == 1
    assert client_creates[0].get("pid", -1) > 4
    assert client_creates[0].get("actorID")
    assert client_creates[0]["timestamp_ms"] != server_reads[0]["timestamp_ms"]
    assert server_reads[0].get("actorID") != client_creates[0].get("actorID")
    assert "target_process_uuid" not in client_creates[0].get("properties", {})
    assert client_creates[0]["objectID"] != server_reads[0]["objectID"]
    assert not any(
        "\\\\FS-01\\Finance" in record.get("properties", {}).get("file_path", "") for record in ecar
    )


def test_encrypted_share_keeps_mapping_and_endpoint_evidence_but_hides_operations(
    scenarios_dir: Path,
    tmp_path: Path,
) -> None:
    data = _base_scenario(scenarios_dir)
    data["environment"]["storage"]["servers"][0]["volumes"][0]["filesystem"] = "refs"
    data["environment"]["storage"]["servers"][0]["shares"][0]["encryption"] = "required"
    data["storyline"] = [
        {
            "id": "encrypted-read",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Read an encrypted-share forecast",
            "events": [
                {
                    "type": "smb_activity",
                    "operation": "read",
                    "target": {
                        "type": "share",
                        "share": "FS-01.finance",
                        "file_ref": "forecast",
                    },
                    "outcome": "success",
                }
            ],
        }
    ]

    GenerationEngine(Scenario(**data), tmp_path, resource_forecast=_forecast(tmp_path)).generate()

    endpoint_records = _json_records(tmp_path, "ecar.json")
    mappings = _json_records(tmp_path, "smb_mapping.json")
    assert any(record.get("service") == "Finance" for record in mappings)
    assert {
        record["native_file_system"] for record in mappings if record["service"] == "Finance"
    } == {"ReFS"}
    assert not any(
        record.get("name") == "forecast.xlsx"
        for record in _json_records(tmp_path, "smb_files.json")
    )
    assert not any(
        str(record.get("filename", "")).endswith("forecast.xlsx")
        for record in _json_records(tmp_path, "files.json")
    )
    assert any(
        record.get("hostname") == "FS-01"
        and record.get("action") == "READ"
        and str(record.get("properties", {}).get("file_path", "")).endswith("forecast.xlsx")
        for record in endpoint_records
    ), endpoint_records


def test_external_smb_client_keeps_network_locality_and_server_only_endpoint_evidence(
    scenarios_dir: Path,
    tmp_path: Path,
) -> None:
    data = _base_scenario(scenarios_dir)
    data["storyline"] = [
        {
            "id": "external-read",
            "time": "+10m",
            "actor": "test_user",
            "system": "FS-01",
            "activity": "An unmodeled client reads a share",
            "events": [
                {
                    "type": "smb_activity",
                    "client": {"type": "external", "ip": "198.51.100.42"},
                    "operation": "read",
                    "target": {
                        "type": "share",
                        "share": "FS-01.finance",
                        "file_ref": "forecast",
                    },
                    "outcome": "success",
                }
            ],
        }
    ]

    GenerationEngine(Scenario(**data), tmp_path, resource_forecast=_forecast(tmp_path)).generate()

    connection = next(
        record
        for record in _json_records(tmp_path, "conn.json")
        if record.get("id.orig_h") == "198.51.100.42" and record.get("id.resp_p") == 445
    )
    file_record = next(
        record
        for record in _json_records(tmp_path, "files.json")
        if str(record.get("filename", "")).endswith("forecast.xlsx")
        and connection["uid"] in record.get("conn_uids", [])
    )
    assert connection["local_orig"] is False
    assert file_record["local_orig"] is False
    assert file_record["is_orig"] is False
    assert not any(
        record.get("hostname") == "198.51.100.42" for record in _json_records(tmp_path, "ecar.json")
    )
    assert any(
        record.get("hostname") == "FS-01"
        and record.get("object") == "FILE"
        and record.get("action") == "READ"
        for record in _json_records(tmp_path, "ecar.json")
    )
